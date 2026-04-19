package adapter

import (
	"context"
	"fmt"
	"time"

	"github.com/org/identity-fabric/services/token-exchange/internal/canonical"
)

type SessionStore interface {
	Lookup(ctx context.Context, sessionID string) (*SessionData, error)
}

type SessionData struct {
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id"`
	Roles     []string  `json:"roles"`
	Issuer    string    `json:"issuer"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OpaqueAdapter struct {
	store SessionStore
}

func NewOpaqueAdapter(store SessionStore) *OpaqueAdapter {
	return &OpaqueAdapter{store: store}
}

func (a *OpaqueAdapter) TokenType() TokenType {
	return TokenTypeOpaque
}

func (a *OpaqueAdapter) Detect(token string) bool {
	if len(token) < 16 || len(token) > 256 {
		return false
	}
	for _, c := range token {
		if !isAlphanumericOrDash(c) {
			return false
		}
	}
	return true
}

func (a *OpaqueAdapter) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	session, err := a.store.Lookup(ctx, req.SubjectToken)
	if err != nil {
		return nil, fmt.Errorf("session lookup failed: %w", err)
	}

	return &ExchangeResult{
		Subject: fmt.Sprintf("user:%s", session.UserID),
		IdentityClaims: canonical.IdentityClaims{
			OrgID:          session.OrgID,
			Roles:          session.Roles,
			AuthMethod:     string(canonical.AuthLegacy),
			OriginalIssuer: session.Issuer,
			TrustLevel:     string(canonical.TrustMedium),
		},
	}, nil
}

func isAlphanumericOrDash(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}
