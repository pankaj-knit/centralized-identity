package identity

import "errors"

var (
	ErrMissingToken      = errors.New("identity: missing bearer token")
	ErrInsufficientTrust = errors.New("identity: insufficient trust level")
	ErrPCIScopeRequired  = errors.New("identity: PCI scope required for this resource")
	ErrForbidden         = errors.New("identity: insufficient permissions")
	ErrTokenExpired      = errors.New("identity: token expired")
	ErrInvalidIssuer     = errors.New("identity: untrusted token issuer")
)
