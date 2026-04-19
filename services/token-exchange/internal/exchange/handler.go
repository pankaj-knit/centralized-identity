package exchange

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/org/identity-fabric/services/token-exchange/internal/adapter"
	"github.com/org/identity-fabric/services/token-exchange/internal/canonical"
	"github.com/org/identity-fabric/services/token-exchange/internal/observability"
)

type TokenExchangeRequest struct {
	GrantType        string `json:"grant_type"`
	SubjectToken     string `json:"subject_token"`
	SubjectTokenType string `json:"subject_token_type"`
	Audience         string `json:"audience,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

type Handler struct {
	registry *adapter.Registry
	minter   *canonical.Minter
}

func NewHandler(registry *adapter.Registry, minter *canonical.Minter) *Handler {
	return &Handler{
		registry: registry,
		minter:   minter,
	}
}

const grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}

	var req TokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	if req.GrantType != grantTypeTokenExchange {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("expected %s", grantTypeTokenExchange))
		return
	}

	if req.SubjectToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	observability.Info(ctx, "exchange_request", observability.WithAdapter(req.SubjectTokenType))

	result, err := h.exchange(ctx, req, w)
	if err != nil {
		observability.Error(ctx, "exchange_failed", observability.WithError(err))
		writeError(w, http.StatusUnauthorized, "invalid_grant", err.Error())
		return
	}

	observability.Info(ctx, "exchange_success", observability.WithAdapter(result.IssuedTokenType))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) exchange(ctx context.Context, req TokenExchangeRequest, w http.ResponseWriter) (*TokenExchangeResponse, error) {
	tracer := observability.Tracer()

	tokenType := adapter.TokenType(req.SubjectTokenType)
	var adp adapter.Adapter
	var err error

	ctx, resolveSpan := tracer.Start(ctx, "resolve_adapter",
		trace.WithAttributes(attribute.String("token_type_hint", string(tokenType))),
	)
	if tokenType != "" {
		adp, err = h.registry.Get(tokenType)
		if err != nil {
			resolveSpan.SetStatus(codes.Error, err.Error())
			resolveSpan.End()
			return nil, fmt.Errorf("unsupported token type: %s", tokenType)
		}
	} else {
		var detected bool
		adp, detected = h.registry.Detect(req.SubjectToken)
		if !detected {
			resolveSpan.SetStatus(codes.Error, "auto-detect failed")
			resolveSpan.End()
			return nil, fmt.Errorf("unable to determine token type; provide subject_token_type")
		}
	}
	adapterName := string(adp.TokenType())
	resolveSpan.SetAttributes(attribute.String("adapter", adapterName))
	resolveSpan.End()

	observability.SetAdapter(w, adapterName)

	ctx, exchangeSpan := tracer.Start(ctx, "adapter_exchange",
		trace.WithAttributes(attribute.String("adapter", adapterName)),
	)
	adapterStart := time.Now()
	exchangeReq := adapter.ExchangeRequest{
		SubjectToken:     req.SubjectToken,
		SubjectTokenType: tokenType,
	}
	result, err := adp.Exchange(ctx, exchangeReq)
	adapterDur := time.Since(adapterStart).Seconds()

	traceID := trace.SpanFromContext(ctx).SpanContext().TraceID().String()
	observability.AdapterDuration.WithLabelValues(adapterName).(prometheus.ExemplarObserver).ObserveWithExemplar(adapterDur, prometheus.Labels{"trace_id": traceID})

	if err != nil {
		exchangeSpan.SetStatus(codes.Error, err.Error())
		exchangeSpan.End()
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	exchangeSpan.SetAttributes(
		attribute.String("subject", result.Subject),
		attribute.String("trust_level", result.IdentityClaims.TrustLevel),
		attribute.String("auth_method", result.IdentityClaims.AuthMethod),
	)
	exchangeSpan.End()

	ctx, mintSpan := tracer.Start(ctx, "mint_canonical_token")
	mintStart := time.Now()
	audience := []string{}
	if req.Audience != "" {
		audience = []string{req.Audience}
	}
	canonicalToken, err := h.minter.Mint(result.Subject, audience, result.IdentityClaims)
	mintDur := time.Since(mintStart).Seconds()
	observability.MintDuration.WithLabelValues().(prometheus.ExemplarObserver).ObserveWithExemplar(mintDur, prometheus.Labels{"trace_id": traceID})

	if err != nil {
		mintSpan.SetStatus(codes.Error, err.Error())
		mintSpan.End()
		return nil, fmt.Errorf("canonical token minting failed: %w", err)
	}
	mintSpan.End()

	observability.TokenTrustLevel.WithLabelValues(result.IdentityClaims.TrustLevel, result.IdentityClaims.AuthMethod).Inc()

	return &TokenExchangeResponse{
		AccessToken:     canonicalToken,
		IssuedTokenType: string(adapter.TokenTypeJWT),
		TokenType:       "Bearer",
		ExpiresIn:       300,
	}, nil
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:       code,
		Description: description,
	})
}
