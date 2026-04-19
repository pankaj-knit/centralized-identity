package adapter

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/org/identity-fabric/services/token-exchange/internal/canonical"
)

type HMACSecret struct {
	ServiceName string
	Secret      []byte
	TrustLevel  canonical.TrustLevel
	DeprecatedAt *time.Time
}

type SecretStore interface {
	GetSecret(ctx context.Context, serviceID string) (*HMACSecret, error)
}

type HMACAdapter struct {
	secrets SecretStore
}

func NewHMACAdapter(secrets SecretStore) *HMACAdapter {
	return &HMACAdapter{secrets: secrets}
}

func (a *HMACAdapter) TokenType() TokenType {
	return TokenTypeHMAC
}

func (a *HMACAdapter) Detect(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var p map[string]any
	if json.Unmarshal(payload, &p) != nil {
		return false
	}
	_, hasServiceID := p["service_id"]
	return hasServiceID
}

func (a *HMACAdapter) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	parts := strings.SplitN(req.SubjectToken, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid HMAC token format: expected payload.signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid HMAC payload encoding: %w", err)
	}

	var payload struct {
		ServiceID string   `json:"service_id"`
		Roles     []string `json:"roles"`
		OrgID     string   `json:"org_id"`
		Timestamp int64    `json:"timestamp"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid HMAC payload: %w", err)
	}

	secret, err := a.secrets.GetSecret(ctx, payload.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("secret lookup failed: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	mac := hmac.New(sha256.New, secret.Secret)
	mac.Write(payloadBytes)
	expected := mac.Sum(nil)

	if !hmac.Equal(signature, expected) {
		return nil, fmt.Errorf("HMAC signature verification failed")
	}

	trustLevel := canonical.TrustLow
	if secret.DeprecatedAt != nil {
		trustLevel = canonical.TrustLow
	}

	return &ExchangeResult{
		Subject: fmt.Sprintf("service:%s", payload.ServiceID),
		IdentityClaims: canonical.IdentityClaims{
			OrgID:          payload.OrgID,
			Roles:          payload.Roles,
			AuthMethod:     string(canonical.AuthLegacy),
			OriginalIssuer: payload.ServiceID,
			TrustLevel:     string(trustLevel),
			ServiceName:    secret.ServiceName,
		},
	}, nil
}
