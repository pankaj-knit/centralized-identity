package identity

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	ServiceName      string
	ExchangeEndpoint string
	PolicyEndpoint   string
	JWKSEndpoint     string

	CacheTTL        time.Duration
	RequestTimeout  time.Duration
}

func DefaultConfig(serviceName string) Config {
	return Config{
		ServiceName:      serviceName,
		ExchangeEndpoint: "http://localhost:8080/v1/token/exchange",
		PolicyEndpoint:   "http://localhost:8181/v1/data",
		JWKSEndpoint:     "http://localhost:8080/.well-known/jwks.json",
		CacheTTL:         60 * time.Second,
		RequestTimeout:   2 * time.Second,
	}
}

type Client struct {
	config    Config
	jwksCache *JWKSCache
	mu        sync.RWMutex
	httpClient *http.Client
}

var (
	globalClient *Client
	initOnce     sync.Once
)

func Init(config Config) error {
	var initErr error
	initOnce = sync.Once{}
	initOnce.Do(func() {
		client, err := newClient(config)
		if err != nil {
			initErr = err
			return
		}
		globalClient = client
	})
	return initErr
}

func newClient(config Config) (*Client, error) {
	if config.ServiceName == "" {
		return nil, fmt.Errorf("identity: ServiceName is required")
	}

	return &Client{
		config: config,
		jwksCache: newJWKSCache(config.JWKSEndpoint, config.CacheTTL),
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
		},
	}, nil
}

func GetClient() *Client {
	if globalClient == nil {
		panic("identity: Init() must be called before GetClient()")
	}
	return globalClient
}

type Identity struct {
	Subject    string
	OrgID      string
	Roles      []string
	AuthMethod string
	TrustLevel string
	PCIScope   bool
	Raw        map[string]any
}

func (c *Client) ValidateToken(ctx context.Context, token string) (*Identity, error) {
	keyFunc, err := c.jwksCache.KeyFunc()
	if err != nil {
		return nil, fmt.Errorf("identity: JWKS fetch failed: %w", err)
	}

	claims, err := validateCanonicalJWT(token, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("identity: token validation failed: %w", err)
	}

	return &Identity{
		Subject:    claims.Subject,
		OrgID:      claims.IdentityClaims.OrgID,
		Roles:      claims.IdentityClaims.Roles,
		AuthMethod: claims.IdentityClaims.AuthMethod,
		TrustLevel: claims.IdentityClaims.TrustLevel,
		PCIScope:   claims.IdentityClaims.PCIScope,
	}, nil
}

func (c *Client) CheckPolicy(ctx context.Context, identity *Identity, resource, action string) (bool, error) {
	input := map[string]any{
		"subject":      identity.Subject,
		"org_id":       identity.OrgID,
		"roles":        identity.Roles,
		"auth_method":  identity.AuthMethod,
		"trust_level":  identity.TrustLevel,
		"resource":     resource,
		"action":       action,
		"service_name": c.config.ServiceName,
	}

	return evaluatePolicy(ctx, c.httpClient, c.config.PolicyEndpoint, input)
}

func (c *Client) ExchangeToken(ctx context.Context, token, tokenType string) (string, error) {
	return exchangeToken(ctx, c.httpClient, c.config.ExchangeEndpoint, token, tokenType)
}
