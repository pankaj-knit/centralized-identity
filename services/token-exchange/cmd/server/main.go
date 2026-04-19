package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/org/identity-fabric/services/token-exchange/internal/adapter"
	"github.com/org/identity-fabric/services/token-exchange/internal/canonical"
	"github.com/org/identity-fabric/services/token-exchange/internal/exchange"
	"github.com/org/identity-fabric/services/token-exchange/internal/observability"
)

func main() {
	ctx := context.Background()

	otlpEndpoint := getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "jaeger:4317")
	shutdown, err := observability.InitTracer(ctx, otlpEndpoint)
	if err != nil {
		log.Printf("warning: tracing init failed (non-fatal): %v", err)
	} else {
		defer shutdown(ctx)
	}

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate signing key: %v", err)
	}

	tokenConfig := canonical.DefaultConfig()
	tokenConfig.SigningKey = signingKey
	tokenConfig.SigningAlg = jwt.SigningMethodES256

	minter := canonical.NewMinter(tokenConfig)

	trustedIssuers := parseTrustedIssuers()
	issuerKeys := fetchAllJWKS(trustedIssuers)

	registry := adapter.NewRegistry()

	jwtAdapter := adapter.NewJWTAdapter(
		adapter.JWTAdapterConfig{
			TrustedIssuers: buildTrustedIssuerConfig(trustedIssuers),
		},
		buildKeyFunc(issuerKeys),
	)
	registry.Register(jwtAdapter)

	opaqueStore := adapter.NewOpaqueAdapter(&httpSessionStore{
		baseURL: getEnv("OPAQUE_VALIDATE_URL", "http://opaque-token-app:9002/validate"),
	})
	registry.Register(opaqueStore)

	samlAdapter := adapter.NewSAMLAdapter(adapter.SAMLConfig{
		TrustedIdPs: map[string]adapter.SAMLIdP{
			"https://legacy-idp.example.com/saml": {
				EntityID:   "https://legacy-idp.example.com/saml",
				TrustLevel: canonical.TrustMedium,
			},
		},
	})
	registry.Register(samlAdapter)

	handler := exchange.NewHandler(registry, minter)

	mux := http.NewServeMux()

	// Wrap the exchange handler with the middleware chain:
	// correlation ID → tracing → metrics → handler
	exchangeHandler := observability.CorrelationMiddleware(
		observability.TracingMiddleware(
			observability.MetricsMiddleware(handler),
		),
	)
	mux.Handle("/v1/token/exchange", exchangeHandler)

	mux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true},
	))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("token-exchange-service listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}

type trustedIssuerEntry struct {
	Name    string
	JWKSURL string
	Trust   string
}

func parseTrustedIssuers() []trustedIssuerEntry {
	raw := getEnv("TRUSTED_ISSUERS", "legacy-jwt-issuer=http://legacy-jwt-app:9001/.well-known/jwks.json,medium")
	var entries []trustedIssuerEntry
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		issuer := parts[0]
		rest := strings.SplitN(parts[1], ",", 2)
		trust := "medium"
		if len(rest) == 2 {
			trust = rest[1]
		}
		entries = append(entries, trustedIssuerEntry{
			Name:    issuer,
			JWKSURL: rest[0],
			Trust:   trust,
		})
	}
	return entries
}

func buildTrustedIssuerConfig(entries []trustedIssuerEntry) map[string]adapter.TrustedIssuer {
	m := make(map[string]adapter.TrustedIssuer, len(entries))
	for _, e := range entries {
		m[e.Name] = adapter.TrustedIssuer{
			Name:       e.Name,
			JWKSURL:    e.JWKSURL,
			TrustLevel: canonical.TrustLevel(e.Trust),
			ClaimMap: adapter.ClaimMapping{
				RolesField: "perms",
				OrgIDField: "org",
			},
		}
	}
	return m
}

type ecJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
}

func fetchAllJWKS(entries []trustedIssuerEntry) map[string]*ecdsa.PublicKey {
	keys := make(map[string]*ecdsa.PublicKey)
	client := &http.Client{Timeout: 5 * time.Second}

	for _, entry := range entries {
		for attempt := 0; attempt < 10; attempt++ {
			resp, err := client.Get(entry.JWKSURL)
			if err != nil {
				log.Printf("JWKS fetch attempt %d for %s failed: %v", attempt+1, entry.Name, err)
				time.Sleep(2 * time.Second)
				continue
			}

			var jwks struct {
				Keys []ecJWK `json:"keys"`
			}
			json.NewDecoder(resp.Body).Decode(&jwks)
			resp.Body.Close()

			for _, k := range jwks.Keys {
				if k.Kty != "EC" {
					continue
				}
				pub, err := parseECPublicKey(k)
				if err != nil {
					log.Printf("failed to parse key %s: %v", k.Kid, err)
					continue
				}
				keys[entry.Name] = pub
				log.Printf("loaded JWKS key for issuer %s (kid=%s)", entry.Name, k.Kid)
			}

			if _, ok := keys[entry.Name]; ok {
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	return keys
}

func parseECPublicKey(k ecJWK) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func buildKeyFunc(issuerKeys map[string]*ecdsa.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("unexpected claims type")
		}
		issuer, _ := claims.GetIssuer()
		key, exists := issuerKeys[issuer]
		if !exists {
			return nil, fmt.Errorf("no key for issuer: %s", issuer)
		}
		return key, nil
	}
}

type httpSessionStore struct {
	baseURL string
}

func (s *httpSessionStore) Lookup(ctx context.Context, sessionID string) (*adapter.SessionData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Session-Token", sessionID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid session (status %d)", resp.StatusCode)
	}

	var data adapter.SessionData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("session response parse failed: %w", err)
	}
	return &data, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
