package adapter

import (
	"context"
	"fmt"

	"github.com/org/identity-fabric/services/token-exchange/internal/canonical"
)

type TokenType string

const (
	TokenTypeJWT    TokenType = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccess TokenType = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeSAML2  TokenType = "urn:ietf:params:oauth:token-type:saml2"
	TokenTypeHMAC   TokenType = "urn:identity-fabric:token-type:hmac"
	TokenTypeOpaque TokenType = "urn:identity-fabric:token-type:opaque"
)

type ExchangeRequest struct {
	SubjectToken     string    `json:"subject_token"`
	SubjectTokenType TokenType `json:"subject_token_type"`
	Audience         []string  `json:"audience,omitempty"`
	Scope            []string  `json:"scope,omitempty"`
	RequestedType    TokenType `json:"requested_token_type,omitempty"`
}

type ExchangeResult struct {
	Subject        string
	IdentityClaims canonical.IdentityClaims
}

type Adapter interface {
	TokenType() TokenType
	Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error)
	Detect(token string) bool
}

type Registry struct {
	adapters map[TokenType]Adapter
}

func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[TokenType]Adapter),
	}
}

func (r *Registry) Register(a Adapter) {
	r.adapters[a.TokenType()] = a
}

func (r *Registry) Get(tokenType TokenType) (Adapter, error) {
	a, ok := r.adapters[tokenType]
	if !ok {
		return nil, fmt.Errorf("no adapter registered for token type: %s", tokenType)
	}
	return a, nil
}

func (r *Registry) Detect(token string) (Adapter, bool) {
	for _, a := range r.adapters {
		if a.Detect(token) {
			return a, true
		}
	}
	return nil, false
}
