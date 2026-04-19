package canonical

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TrustLevel string

const (
	TrustHigh   TrustLevel = "high"
	TrustMedium TrustLevel = "medium"
	TrustLow    TrustLevel = "low"
)

type AuthMethod string

const (
	AuthOIDC   AuthMethod = "oidc"
	AuthSAML   AuthMethod = "saml"
	AuthMTLS   AuthMethod = "mtls"
	AuthLegacy AuthMethod = "legacy"
)

type IdentityClaims struct {
	OrgID          string   `json:"org_id"`
	Roles          []string `json:"roles"`
	AuthMethod     string   `json:"auth_method"`
	OriginalIssuer string   `json:"original_issuer"`
	TrustLevel     string   `json:"trust_level"`
	PCIScope       bool     `json:"pci_scope"`
	ServiceName    string   `json:"service_name,omitempty"`
}

type CanonicalClaims struct {
	jwt.RegisteredClaims
	Claims IdentityClaims `json:"claims"`
}

type TokenConfig struct {
	Issuer     string
	DefaultTTL time.Duration
	PCITTL     time.Duration
	SigningKey  any
	SigningAlg jwt.SigningMethod
}

func DefaultConfig() TokenConfig {
	return TokenConfig{
		Issuer:     "identity-fabric.internal",
		DefaultTTL: 5 * time.Minute,
		PCITTL:     60 * time.Second,
	}
}

type Minter struct {
	config TokenConfig
}

func NewMinter(config TokenConfig) *Minter {
	return &Minter{config: config}
}

func (m *Minter) Mint(subject string, audience []string, claims IdentityClaims) (string, error) {
	now := time.Now()
	ttl := m.config.DefaultTTL
	if claims.PCIScope {
		ttl = m.config.PCITTL
	}

	canonical := CanonicalClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.config.Issuer,
			Subject:   subject,
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		Claims: claims,
	}

	token := jwt.NewWithClaims(m.config.SigningAlg, canonical)
	return token.SignedString(m.config.SigningKey)
}

type Validator struct {
	issuer       string
	keyFunc      jwt.Keyfunc
	parserOpts   []jwt.ParserOption
}

func NewValidator(issuer string, keyFunc jwt.Keyfunc) *Validator {
	return &Validator{
		issuer:  issuer,
		keyFunc: keyFunc,
		parserOpts: []jwt.ParserOption{
			jwt.WithIssuer(issuer),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
		},
	}
}

func (v *Validator) Validate(tokenString string) (*CanonicalClaims, error) {
	parser := jwt.NewParser(v.parserOpts...)

	token, err := parser.ParseWithClaims(tokenString, &CanonicalClaims{}, v.keyFunc)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CanonicalClaims)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	return claims, nil
}
