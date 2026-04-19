package identity

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const identityKey contextKey = "identity-fabric-identity"

func AuthMiddleware() func(http.Handler) http.Handler {
	return AuthMiddlewareWithOptions(MiddlewareOptions{})
}

type MiddlewareOptions struct {
	SkipPaths      []string
	RequireTrust   string
	RequirePCI     bool
	OnError        func(w http.ResponseWriter, r *http.Request, err error)
}

func AuthMiddlewareWithOptions(opts MiddlewareOptions) func(http.Handler) http.Handler {
	client := GetClient()

	skipSet := make(map[string]bool, len(opts.SkipPaths))
	for _, p := range opts.SkipPaths {
		skipSet[p] = true
	}

	errorHandler := opts.OnError
	if errorHandler == nil {
		errorHandler = defaultErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skipSet[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			token := extractBearerToken(r)
			if token == "" {
				errorHandler(w, r, ErrMissingToken)
				return
			}

			identity, err := client.ValidateToken(r.Context(), token)
			if err != nil {
				errorHandler(w, r, err)
				return
			}

			if opts.RequireTrust != "" && !meetsMinTrust(identity.TrustLevel, opts.RequireTrust) {
				errorHandler(w, r, ErrInsufficientTrust)
				return
			}

			if opts.RequirePCI && !identity.PCIScope {
				errorHandler(w, r, ErrPCIScopeRequired)
				return
			}

			ctx := context.WithValue(r.Context(), identityKey, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := FromContext(r.Context())
			if id == nil {
				defaultErrorHandler(w, r, ErrMissingToken)
				return
			}

			for _, r := range id.Roles {
				if r == role {
					next.ServeHTTP(w, r.Request)
					return
				}
			}

			defaultErrorHandler(w, r.Request, ErrForbidden)
		})
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

var trustOrder = map[string]int{
	"low":    0,
	"medium": 1,
	"high":   2,
}

func meetsMinTrust(actual, required string) bool {
	return trustOrder[actual] >= trustOrder[required]
}

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	switch err {
	case ErrMissingToken:
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"missing or invalid bearer token"}`))
	case ErrInsufficientTrust:
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden","message":"insufficient trust level"}`))
	case ErrPCIScopeRequired:
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden","message":"PCI scope required"}`))
	case ErrForbidden:
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden","message":"insufficient permissions"}`))
	default:
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"token validation failed"}`))
	}
}
