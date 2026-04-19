# ADR-001: Canonical Token Format

**Status:** Accepted
**Date:** 2026-04-17
**Deciders:** Identity Infrastructure Team

## Context

We have 4+ token formats in production: custom JWTs with non-standard claims, opaque session tokens, HMAC-signed blobs, and SAML assertions. Cross-service communication requires bespoke integration for every pair of services.

We need a single internal token format that all services can understand, regardless of how the caller originally authenticated.

## Decision

Adopt a **canonical JWT** with standardized claims as the internal identity representation:

```json
{
  "iss": "identity-fabric.internal",
  "sub": "service:order-api | user:<uuid>",
  "aud": ["target-service"],
  "exp": <now + 5min>,
  "iat": <now>,
  "jti": "<uuid>",
  "claims": {
    "org_id": "tenant-123",
    "roles": ["order.read", "order.write"],
    "auth_method": "oidc|saml|mtls|legacy",
    "original_issuer": "keycloak|legacy-sso|service-x",
    "trust_level": "high|medium|low",
    "pci_scope": true|false,
    "service_name": "order-api"
  }
}
```

Key design choices:
- **Nested `claims` object** — Separates standard JWT claims from identity-fabric-specific metadata
- **`trust_level`** — Encodes the strength of the original authentication method (OIDC/mTLS = high, custom JWT = medium, HMAC = low)
- **`auth_method` + `original_issuer`** — Preserves provenance for audit and downstream policy decisions
- **`pci_scope`** — Explicit flag for PCI CDE boundary enforcement
- **Short TTL (5 min default, 60s for PCI)** — Limits blast radius of token compromise

Signing: ECDSA P-256 (ES256) via Vault Transit engine. Key rotation automated, JWKS endpoint for validation.

## Alternatives Considered

1. **PASETO tokens** — Better security properties but lower ecosystem support. Teams would need new libraries.
2. **Opaque tokens with introspection** — Adds a network hop for every validation. Unacceptable for latency-sensitive services.
3. **Adopt Keycloak tokens directly** — Ties us to one IdP vendor. Can't represent service identities cleanly.

## Consequences

- All adapters must translate their token format into this canonical structure
- JWKS cache on every service (sidecar or SDK) — no network hop for validation
- `trust_level` enables graduated access control during migration period
- PCI CDE services can enforce `trust_level: high` + `pci_scope: true` as a hard requirement
