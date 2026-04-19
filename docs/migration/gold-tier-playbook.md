# Gold Tier Migration Playbook

## Overview

Gold tier is **full native integration** with the Identity Fabric. Teams replace custom auth code with the Identity SDK one-liner, use Keycloak OIDC natively, and retire all bespoke token handling.

## Prerequisites

- Service is at Silver tier (active policy enforcement working)
- Team has observed stable auth patterns for 2+ weeks at Silver

## What Teams Get

- **Sub-millisecond auth** — Embedded SDK, no sidecar proxy hop (<0.3ms p99)
- **Zero-touch security upgrades** — New standards auto-applied via SDK updates
- **Net code deletion** — Remove 500-2000 lines of custom auth logic
- **Incident ownership transfer** — Identity team handles auth incidents for Gold services
- **Priority platform support** — Dedicated Slack channel, 15-min response SLA

## What Teams Do

1. Integrate the Identity SDK into their service
2. Migrate to Keycloak OIDC for token issuance
3. Remove custom token generation/validation code
4. Remove the sidecar (SDK handles everything)

## Latency Impact

**< 0.3ms p99** — SDK validates locally with cached JWKS, evaluates policy via embedded WASM. This is typically **faster** than the Silver tier sidecar.

## Step-by-Step Migration

### Step 1: Add SDK Dependency (Day 1)

```bash
go get github.com/org/identity-fabric/sdk/go@latest
```

### Step 2: Initialize the SDK (Day 1)

```go
package main

import (
    identity "github.com/org/identity-fabric/sdk/go"
)

func main() {
    err := identity.Init(identity.DefaultConfig("your-service-name"))
    if err != nil {
        log.Fatal(err)
    }

    router := http.NewServeMux()
    // The middleware handles token validation + policy enforcement
    handler := identity.AuthMiddleware()(router)
    http.ListenAndServe(":8080", handler)
}
```

### Step 3: Access Identity in Handlers (Day 2)

```go
func handleOrder(w http.ResponseWriter, r *http.Request) {
    id := identity.FromContext(r.Context())

    // id.Subject  → "user:uuid" or "service:name"
    // id.Roles    → ["order.read", "order.write"]
    // id.OrgID    → "tenant-123"
    // id.TrustLevel → "high"
}
```

### Step 4: Migrate Token Issuance to Keycloak (Sprint 1-2)

For user-facing endpoints:
- Configure Keycloak client for your service
- Update login flows to use Keycloak OIDC
- Map existing roles to Keycloak realm roles

For service-to-service:
- Register a Keycloak service account
- Use SDK's `ExchangeToken()` for outbound calls

### Step 5: Remove Legacy Auth Code (Sprint 2-3)

Systematically remove:
- Custom JWT generation/signing code
- Token validation middleware
- In-app role/permission checking logic
- Session management code (if using opaque tokens)
- HMAC shared secret configuration

### Step 6: Remove Sidecar (Sprint 3)

Once SDK handles all auth:
```yaml
# Remove sidecar annotation
identity-fabric.io/inject: "false"
```

The SDK now handles everything the sidecar did, with lower latency.

### Step 7: Validate (Sprint 3-4)

- Run load tests to confirm latency improvement
- Verify all auth telemetry still flowing (SDK reports same metrics)
- Confirm compliance reports still generating
- Monitor for 2 weeks in production

## Rollback

1. Re-enable sidecar (Silver tier fallback)
2. SDK and sidecar can coexist — sidecar acts as backup

## Success Criteria

- [ ] SDK initialized and handling all auth
- [ ] All tokens issued via Keycloak OIDC
- [ ] Legacy auth code removed
- [ ] Sidecar removed
- [ ] Auth latency < 0.3ms p99
- [ ] Zero auth-related incidents for 30 days
- [ ] Compliance reports auto-generating

## Timeline

**2-4 sprints** (4-8 weeks), primarily team effort with identity team embedded support.
