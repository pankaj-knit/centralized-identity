package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/org/identity-fabric/services/token-exchange/internal/canonical"
)

type JWTAdapterConfig struct {
	TrustedIssuers map[string]TrustedIssuer
}

type TrustedIssuer struct {
	Name       string
	JWKSURL    string
	TrustLevel canonical.TrustLevel
	ClaimMap   ClaimMapping
}

type ClaimMapping struct {
	SubjectField string
	RolesField   string
	OrgIDField   string
}

type JWTAdapter struct {
	config  JWTAdapterConfig
	keyFunc jwt.Keyfunc
}

func NewJWTAdapter(config JWTAdapterConfig, keyFunc jwt.Keyfunc) *JWTAdapter {
	return &JWTAdapter{
		config:  config,
		keyFunc: keyFunc,
	}
}

func (a *JWTAdapter) TokenType() TokenType {
	return TokenTypeJWT
}

func (a *JWTAdapter) Detect(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	// Verify the header is valid JSON with "alg" field
	header, err := jwt.NewParser().DecodeSegment(parts[0])
	if err != nil {
		return false
	}
	var h map[string]any
	return json.Unmarshal(header, &h) == nil && h["alg"] != nil
}

func (a *JWTAdapter) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	parser := jwt.NewParser(jwt.WithExpirationRequired())

	token, err := parser.Parse(req.SubjectToken, a.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("jwt validation failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	issuer, _ := claims.GetIssuer()
	trusted, exists := a.config.TrustedIssuers[issuer]
	if !exists {
		return nil, fmt.Errorf("untrusted issuer: %s", issuer)
	}

	subject := extractClaim(claims, trusted.ClaimMap.SubjectField, "sub")
	roles := extractStringSlice(claims, trusted.ClaimMap.RolesField, "roles")
	orgID := extractClaim(claims, trusted.ClaimMap.OrgIDField, "org_id")

	return &ExchangeResult{
		Subject: subject,
		IdentityClaims: canonical.IdentityClaims{
			OrgID:          orgID,
			Roles:          roles,
			AuthMethod:     string(canonical.AuthLegacy),
			OriginalIssuer: issuer,
			TrustLevel:     string(trusted.TrustLevel),
		},
	}, nil
}

func extractClaim(claims jwt.MapClaims, preferred, fallback string) string {
	field := preferred
	if field == "" {
		field = fallback
	}
	if val, ok := claims[field]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func extractStringSlice(claims jwt.MapClaims, preferred, fallback string) []string {
	field := preferred
	if field == "" {
		field = fallback
	}
	val, ok := claims[field]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case string:
		return strings.Split(v, ",")
	default:
		return nil
	}
}
