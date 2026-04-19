# Identity Fabric: Unified Identity Infrastructure Design

## Executive Summary

This document presents a design for consolidating a fragmented identity landscape (custom JWTs, opaque tokens, HMAC blobs, SAML, mTLS, Keycloak) into a unified **Identity Fabric** — an abstraction layer that standardizes authentication and authorization across 500+ services without requiring a big-bang migration.

**Key promise to business teams:** Zero-downtime adoption, no release blockers, and measurable latency improvement over current ad-hoc implementations.

---

## 1. Current State Analysis

### 1.1 Token Landscape

| Token Type | Risk Profile | Typical Usage | Migration Complexity |
|------------|-------------|---------------|---------------------|
| Custom JWTs | HIGH — inconsistent signing, no rotation | Service-to-service, some user-facing | Medium — already JWT, need claim standardization |
| Opaque session tokens | MEDIUM — centralized validation creates SPOF | User sessions, legacy web apps | High — requires session architecture change |
| HMAC-signed blobs | CRITICAL — shared secrets, no expiry enforcement | Legacy integrations, batch jobs | High — need to inventory all shared secrets |
| SAML assertions | MEDIUM — aging protocol, XML parsing overhead | Enterprise SSO, partner federations | Medium — SAML-to-OIDC bridge is well-understood |
| Keycloak OIDC | LOW — standards-based, closest to target state | Newer services | Low — already on target protocol |
| mTLS certificates | LOW — strong auth, but no authorization context | Infrastructure services | Low — complement with identity claims |

### 1.2 Key Problems

1. **No canonical identity** — The same user/service has different identity representations across systems
2. **AuthZ coupled to AuthN** — Authorization logic is baked into each service, duplicated and inconsistent
3. **Compliance burden** — Every team independently satisfies SOC2/PCI-DSS audit requirements
4. **Secret sprawl** — HMAC shared secrets and custom JWT signing keys scattered across services
5. **No cross-service trust** — Team A's token means nothing to Team B's service

---

## 2. Target Architecture: Identity Fabric

### 2.1 Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                      IDENTITY CONTROL PLANE                       │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Policy Admin  │  │ Key Mgmt     │  │ Observability &        │  │
│  │ (GitOps)      │  │ (Vault)      │  │ Compliance Dashboard   │  │
│  └──────────────┘  └──────────────┘  └────────────────────────┘  │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Service       │  │ Migration    │  │ Developer              │  │
│  │ Registry      │  │ Tracker      │  │ Self-Service Portal    │  │
│  └──────────────┘  └──────────────┘  └────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
   ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
   │   TOKEN      │    │  POLICY     │    │ CREDENTIAL  │
   │   EXCHANGE   │    │  DECISION   │    │  LIFECYCLE  │
   │   SERVICE    │    │  POINT      │    │  MANAGER    │
   │              │    │             │    │             │
   │  RFC 8693    │    │  OPA/Cedar  │    │  Vault +    │
   │  + adapters  │    │  (embedded) │    │  Keycloak   │
   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
          │                   │                   │
   ┌──────▼───────────────────▼───────────────────▼──────┐
   │                                                      │
   │              IDENTITY DATA PLANE                      │
   │                                                      │
   │  ┌─────────────────┐    ┌─────────────────────────┐  │
   │  │  Sidecar Proxy   │    │  Embedded SDK            │  │
   │  │  (K8s services)  │    │  (VMs, serverless, low-  │  │
   │  │                  │    │   latency hot paths)      │  │
   │  └─────────────────┘    └─────────────────────────┘  │
   │                                                      │
   └──┬───────────┬───────────┬───────────┬──────────────┘
      │           │           │           │
  ┌───▼───┐  ┌───▼───┐  ┌───▼────┐  ┌───▼────┐
  │Custom │  │Opaque │  │SAML    │  │Keycloak│
  │JWT    │  │Token  │  │Legacy  │  │OIDC    │
  │Apps   │  │Apps   │  │SSO     │  │Apps    │
  └───────┘  └───────┘  └────────┘  └────────┘
```

### 2.2 Component Breakdown

#### A. Token Exchange Service (TES)

**Purpose:** Universal token translator — accepts any token format, emits a canonical internal JWT.

**Design:**

```
                    Incoming Request
                          │
                    ┌─────▼─────┐
                    │  Token     │
                    │  Classifier│  ← Auto-detects token type
                    └─────┬─────┘
                          │
            ┌─────────────┼─────────────┐─────────────┐
            │             │             │             │
      ┌─────▼────┐  ┌────▼─────┐ ┌────▼─────┐ ┌────▼─────┐
      │ JWT       │  │ Opaque   │ │ SAML     │ │ HMAC     │
      │ Adapter   │  │ Adapter  │ │ Adapter  │ │ Adapter  │
      └─────┬────┘  └────┬─────┘ └────┬─────┘ └────┬─────┘
            │             │             │             │
            └─────────────┼─────────────┘─────────────┘
                          │
                    ┌─────▼─────┐
                    │  Canonical │
                    │  Token     │  → Standard JWT with unified claims
                    │  Minter    │
                    └───────────┘
```

**Canonical Token Format:**
```json
{
  "iss": "identity-fabric.internal",
  "sub": "service:order-api OR user:uuid",
  "aud": ["target-service"],
  "exp": 1700000000,
  "iat": 1699999700,
  "jti": "unique-token-id",
  "claims": {
    "org_id": "tenant-123",
    "roles": ["order.read", "order.write"],
    "auth_method": "oidc|saml|mtls|legacy",
    "original_issuer": "keycloak|legacy-sso|service-x",
    "trust_level": "high|medium|low",
    "pci_scope": true
  }
}
```

**Key Design Decisions:**
- `trust_level` reflects the strength of the original authentication (OIDC/mTLS = high, HMAC blob = low)
- `auth_method` preserves provenance — downstream services can make decisions based on how the caller authenticated
- `pci_scope` flag for PCI-DSS cardholder data environment (CDE) access control
- Short-lived (5 min default) — never stored, always exchanged fresh

**Latency Mitigation:**
- JWKS cached locally with 60s TTL (eliminates validation round-trips)
- Token Exchange results cached with sliding window (same input → same output, no re-exchange)
- Opaque token adapter uses async batch validation for non-critical paths
- Hot path: **< 1ms** for cached JWT validation, **< 5ms** for token exchange

#### B. Policy Decision Point (PDP)

**Purpose:** Centralized authorization logic, decoupled from authentication mechanism.

**Why OPA/Cedar:**
- Policy-as-code in Git (teams own their policies, reviewed like code)
- Evaluates locally — no network hop for authorization decisions
- Rich policy language handles RBAC, ABAC, and relationship-based access
- PCI-DSS: audit trail of every policy decision

**Deployment Modes:**

| Mode | Where | Latency | Use Case |
|------|-------|---------|----------|
| Embedded (WASM) | Inside sidecar/SDK | < 0.1ms | Hot path APIs, latency-critical |
| Sidecar daemon | Localhost gRPC | < 1ms | Standard K8s services |
| Central PDP cluster | Network call | 2-5ms | Batch jobs, async workflows |

**Policy Structure (per team):**
```
policies/
├── order-service/
│   ├── authz.rego          # Who can call this service
│   ├── data-access.rego    # Row-level / field-level access
│   └── pci-overrides.rego  # PCI-specific restrictions
├── shared/
│   ├── pci-baseline.rego   # Org-wide PCI rules (identity team owns)
│   └── soc2-logging.rego   # Mandatory audit logging rules
```

**Teams define:** their service-specific authZ rules.
**Identity team enforces:** org-wide compliance baselines that cannot be overridden.

#### C. Credential Lifecycle Manager (CLM)

**Purpose:** Automate credential issuance, rotation, and revocation.

**Components:**
- **Vault** — Secret storage, dynamic credential generation, automatic rotation
- **Keycloak** — OIDC token issuance, user federation, service account management
- **Certificate Authority** — Internal CA for mTLS certificates (short-lived, auto-rotated)

**Key Flows:**

1. **Service Identity Bootstrap:**
   ```
   Service starts → Retrieves SPIFFE identity from platform →
   Exchanges for Keycloak service account token →
   Receives short-lived canonical JWT → Ready to make calls
   ```

2. **Secret Rotation (PCI-DSS):**
   ```
   Vault rotates signing keys on schedule →
   Publishes new JWKS to local caches →
   Old keys valid for grace period →
   Automatic, zero-downtime rotation
   ```

3. **HMAC Shared Secret Elimination:**
   ```
   Inventory all HMAC secrets via CLM →
   Issue temporary dual-validation (HMAC + canonical JWT) →
   Monitor: when 100% traffic uses canonical JWT →
   Revoke HMAC secret
   ```

#### D. Identity Data Plane (Sidecar + SDK)

**The critical decision:** Sidecar vs SDK is not either/or. It's a deployment spectrum.

```
┌─────────────────────────────────────────────────────────┐
│                   DEPLOYMENT MATRIX                       │
├──────────────┬──────────────┬───────────────────────────┤
│ Environment  │ Default Mode │ Override Available        │
├──────────────┼──────────────┼───────────────────────────┤
│ K8s          │ Sidecar      │ SDK for < 1ms budget      │
│ VMs          │ SDK (agent)  │ Sidecar via VM agent      │
│ Serverless   │ SDK (lib)    │ N/A (no sidecar possible) │
│ Batch/Cron   │ SDK (lib)    │ Central PDP call          │
└──────────────┴──────────────┴───────────────────────────┘
```

**Sidecar Responsibilities:**
1. Intercept inbound requests → validate token → enrich headers with canonical claims
2. Intercept outbound requests → attach/exchange token for target service
3. Evaluate authorization policy (embedded OPA)
4. Report telemetry (who called whom, with what permission, latency overhead)

**SDK Responsibilities (same logic, different packaging):**
1. Middleware/interceptor for HTTP/gRPC frameworks
2. Token validation with local JWKS cache
3. Embedded policy evaluation
4. Available in: Java, Go, Python, Node.js, .NET

**SDK Design Principle — One-Line Init:**
```
// Go example
identityfabric.Init(identityfabric.Config{
    ServiceName: "order-api",
    // Everything else auto-discovered from platform
})

// The middleware handles everything:
router.Use(identityfabric.AuthMiddleware())
```

---

## 3. Migration Strategy

### 3.1 Phased Approach — "Wrap, Then Replace"

The central insight: **don't ask teams to change their auth code. Put a translator in front of it.**

```
Phase 0          Phase 1           Phase 2           Phase 3
(Current)        (Wrap)            (Standardize)     (Converge)
                                                    
┌─────────┐     ┌─────────────┐   ┌──────────────┐  ┌──────────────┐
│ Custom   │     │ Sidecar     │   │ Sidecar      │  │ SDK/Sidecar  │
│ JWT      │ →   │ validates   │ → │ exchanges    │→ │ native OIDC  │
│ (direct) │     │ custom JWT  │   │ to canonical │  │ (custom JWT  │
│          │     │ + reports   │   │ JWT          │  │  retired)    │
└─────────┘     └─────────────┘   └──────────────┘  └──────────────┘
                                                    
 No change        Sidecar deploy    Config change     Code change
 needed           (platform team)   (team + platform) (team owns)
```

### 3.2 Tier System

#### Bronze Tier — "Observe & Bridge" (Week 1-4 per team)

**What the platform team does (no team involvement needed):**
- Deploy identity sidecar alongside service (K8s admission controller or VM agent)
- Sidecar operates in **passive mode**: observes all auth traffic, reports to dashboard
- Token Exchange Service accepts team's current tokens for cross-service calls

**What teams get immediately:**
- Dashboard: "who calls your service, with what identity, using what auth method"
- Cross-service interoperability: other teams can call you via canonical token
- Compliance report: auto-generated evidence for SOC2 access reviews
- Alert on anomalies: unusual callers, expired tokens being accepted, etc.

**Team effort: ZERO.** Platform team deploys, team gets value.

**Latency impact: ~0.5ms** (passive observation, no blocking validation)

#### Silver Tier — "Standardize AuthZ" (Month 2-4 per team)

**What teams do:**
- Move authorization logic from application code to policy-as-code (OPA/Cedar)
- Adopt canonical token for new endpoints (existing endpoints keep working)
- Enable sidecar active mode: sidecar enforces policy, not the application

**What teams get:**
- Self-service policy testing portal ("will this request be allowed?")
- Automatic credential rotation (no more manual secret management)
- PCI-DSS compliance evidence auto-generated per endpoint
- **Audit prep drops from ~2 weeks to < 1 day**

**Team effort: 1-2 sprints** (mostly moving existing logic to policy files)

**Latency impact: ~1ms** (local policy evaluation replaces app-level checks — often *faster* than current ad-hoc implementations)

#### Gold Tier — "Native Identity" (Month 4-8 per team)

**What teams do:**
- Replace custom auth code with SDK one-liner
- All endpoints use canonical OIDC tokens via Keycloak
- Retire bespoke token generation/validation code

**What teams get:**
- Embedded SDK: **< 0.3ms** auth overhead (faster than sidecar)
- Zero-touch security upgrades (new standards auto-applied)
- Priority incident support from identity team
- Reduced on-call burden: identity incidents handled centrally
- **Net code deletion** — teams remove auth code, not add it

**Team effort: 2-4 sprints** (actual code changes, but well-guided)

**Latency impact: NEGATIVE** — typically *reduces* latency vs. current custom implementations

### 3.3 Migration Priority Matrix

```
                    HIGH business value of migration
                              ▲
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              │  QUICK WINS   │  STRATEGIC    │
              │               │               │
              │  Keycloak     │  Custom JWT   │
              │  services     │  services     │
              │  (already     │  (large       │
              │  close to     │  surface      │
              │  target)      │  area)        │
              │               │               │
LOW effort ───┼───────────────┼───────────────┼─── HIGH effort
              │               │               │
              │  OPPORTUNIST  │  PLAN AHEAD   │
              │               │               │
              │  mTLS         │  Opaque       │
              │  services     │  session      │
              │  (add claims  │  tokens +     │
              │  layer)       │  HMAC blobs   │
              │               │               │
              └───────────────┼───────────────┘
                              │
                              ▼
                    LOW business value of migration
```

**Recommended wave order:**
1. **Wave 1:** Keycloak services → Gold (they're 80% there)
2. **Wave 2:** Custom JWT services → Silver (standardize claims, add policy)
3. **Wave 3:** mTLS services → Silver (add identity claims alongside certs)
4. **Wave 4:** Opaque token + HMAC services → Full migration path

---

## 4. Latency Architecture

This is the #1 concern for business teams. The design specifically ensures auth overhead *decreases* for most services.

### 4.1 Latency Budget Breakdown

```
┌─────────────────────────────────────────────────────┐
│              LATENCY COMPARISON                       │
├────────────────────────┬────────────────────────────┤
│  CURRENT (Typical)     │  IDENTITY FABRIC            │
├────────────────────────┼────────────────────────────┤
│                        │                            │
│  Token validation:     │  Token validation:          │
│  2-15ms (varies by     │  < 1ms (local JWKS cache)  │
│  implementation, some  │                            │
│  hit external service) │                            │
│                        │                            │
│  Authorization:        │  Authorization:             │
│  3-20ms (DB lookup,    │  < 0.1ms (embedded OPA,    │
│  role checks in app)   │  precompiled policy)       │
│                        │                            │
│  Cross-service auth:   │  Cross-service auth:        │
│  10-50ms (token        │  < 2ms (cached exchange,   │
│  exchange, custom      │  pre-fetched tokens)       │
│  handshake)            │                            │
│                        │                            │
│  TOTAL: 15-85ms        │  TOTAL: 1-3ms              │
│  (inconsistent)        │  (predictable, SLA-backed) │
└────────────────────────┴────────────────────────────┘
```

### 4.2 Why It's Faster

1. **Local JWKS cache** — No network call for token validation (current custom JWTs often call a central validation endpoint)
2. **Embedded policy engine** — OPA evaluates in microseconds, vs DB queries for role checks
3. **Connection pooling** — Sidecar maintains persistent connections to Token Exchange, amortizing TLS handshakes
4. **Pre-fetched tokens** — Sidecar proactively refreshes tokens before expiry (zero-latency on the critical path)
5. **No XML parsing** — SAML services see the biggest improvement when migrated off XML-based assertions

### 4.3 Latency Monitoring & SLA

**Published SLA per tier:**
| Tier | p50 Overhead | p99 Overhead | Guarantee |
|------|-------------|-------------|-----------|
| Bronze (passive) | 0.3ms | 0.8ms | < 1ms |
| Silver (active sidecar) | 0.5ms | 1.5ms | < 2ms |
| Gold (embedded SDK) | 0.1ms | 0.5ms | < 1ms |

**If SLA is breached:** Identity team owns the incident, not the service team.

**Canary mechanism:** Every sidecar reports auth latency. Dashboard shows real-time overhead per service. Any service exceeding SLA triggers automatic alert to identity team.

---

## 5. Incentive Structure

### 5.1 Making the New Path Easier Than the Old Path

| Pain Point (Current) | Fabric Solution | Effort to Adopt |
|----------------------|----------------|-----------------|
| "We spend 2 weeks on audit prep" | Auto-generated SOC2/PCI compliance reports at Silver tier | Move authZ to policy files (1 sprint) |
| "Cross-team API integration takes weeks" | Canonical token works everywhere, zero custom integration | Deploy sidecar (0 effort) |
| "We had a security incident from a leaked HMAC key" | Vault-managed, auto-rotated credentials, no shared secrets | Adopt CLM at Silver tier |
| "New security mandates require code changes every time" | Sidecar/SDK handles new standards automatically at Gold tier | One-time migration to Gold |
| "Identity-related on-call pages" | Identity team takes ownership for Gold tier services | Complete Gold migration |
| "Debugging auth failures is a nightmare" | Distributed tracing of every auth decision, searchable audit log | Available at Bronze (free) |

### 5.2 Organizational Incentives

1. **Compliance fast-track:** Services at Silver+ skip manual evidence collection during audits
2. **Architecture review bypass:** New services starting on Gold tier skip identity-related architecture review (already compliant by default)
3. **Incident SLA transfer:** Gold tier services get identity incidents handled by central identity team with 15-min response SLA
4. **Budget relief:** Identity team funds the migration effort (sidecar deployment, SDK integration support) — teams don't spend their own engineering budget
5. **Deprecation timeline with escape hatch:** Legacy auth methods get a sunset date (18 months), but teams can request extensions if they demonstrate a migration plan

### 5.3 Internal Marketing

Frame this as a **developer productivity initiative**, not a security mandate:

- "Delete your auth code" — teams remove 500-2000 lines of custom auth logic
- "Ship features, not auth bugs" — auth-related incidents drop to zero for Gold services
- "Integrate with any team in 5 minutes" — canonical token eliminates bespoke integration work
- "One config change, not a rewrite" — Bronze → Silver is a config change, not a code change

---

## 6. PCI-DSS Specific Design

Given PCI-DSS is in scope, the fabric has specific capabilities:

### 6.1 Cardholder Data Environment (CDE) Controls

```
┌─────────────────────────────────────────────┐
│           PCI SCOPE BOUNDARY                 │
│                                              │
│  ┌──────────────┐    ┌──────────────────┐   │
│  │ CDE Service  │    │ Identity Fabric   │   │
│  │              │◄───│ (PCI-hardened     │   │
│  │ - card data  │    │  sidecar mode)    │   │
│  │ - tokenized  │    │                   │   │
│  └──────────────┘    │ - mandatory mTLS  │   │
│                      │ - enhanced logging│   │
│                      │ - trust_level=high│   │
│                      │   required        │   │
│                      │ - session pinning │   │
│                      └──────────────────┘   │
│                                              │
└─────────────────────────────────────────────┘
```

**PCI-specific policies (enforced by identity team, not optional):**
- Services in CDE **must** require `trust_level: high` (OIDC or mTLS auth only)
- Canonical tokens for CDE have 60-second expiry (vs. 5 min standard)
- All CDE access decisions logged to immutable audit store
- Quarterly key rotation enforced by Vault (no manual process)

### 6.2 SOC2 Continuous Compliance

- Every policy decision logged with full context (who, what, when, policy version)
- Policy changes tracked in Git with mandatory review
- Compliance dashboard shows real-time posture per service
- Quarterly access reviews auto-generated from fabric telemetry

---

## 7. Handling Future Security Standards

The abstraction layer is the long-term strategic value:

| Future Change | Without Fabric | With Fabric |
|--------------|---------------|-------------|
| Post-quantum TLS | Every team upgrades TLS libraries | Identity team updates sidecar/SDK, auto-deployed |
| Passkey/FIDO2 adoption | Each app implements WebAuthn | Keycloak adds passkey flow, fabric propagates identity |
| Zero-trust mandate | Every service implements device trust, continuous authN | Policy update + sidecar enhancement, no app changes |
| New compliance framework | Each team interprets and implements controls | Identity team adds baseline policies, auto-enforced |
| Vendor IdP migration (e.g., Keycloak → Okta) | Every service re-integrates | Swap IdP behind fabric, services unaffected |

**This is the strongest pitch to leadership:** "Invest once in the fabric, and every future security mandate is a configuration change, not a multi-team engineering program."

---

## 8. Implementation Roadmap

### Phase 1: Foundation (Months 1-3)

| Week | Deliverable | Owner |
|------|------------|-------|
| 1-2 | Token Exchange Service (JWT + SAML adapters) | Identity team |
| 2-4 | Canonical token format specification | Identity + Architecture |
| 3-6 | Identity sidecar v1 (passive mode) | Identity + Platform |
| 4-8 | OPA policy framework + shared baseline policies | Identity team |
| 6-10 | SDK v1 (Go + Java — highest service count languages) | Identity team |
| 8-12 | Observability dashboard + compliance reporting | Identity + SRE |

### Phase 2: Adopt (Months 3-8)

| Month | Deliverable | Owner |
|-------|------------|-------|
| 3-4 | Wave 1: Keycloak services → Gold (20-30 services) | Identity + teams |
| 4-5 | Opaque token adapter + HMAC adapter in TES | Identity team |
| 4-6 | Wave 2: Custom JWT services → Silver (100+ services) | Identity + teams |
| 5-7 | SDK v2 (Python, Node.js, .NET) | Identity team |
| 6-8 | Wave 3: mTLS services → Silver | Identity + teams |
| 6-8 | Self-service portal for policy testing | Identity team |

### Phase 3: Converge (Months 8-18)

| Month | Deliverable | Owner |
|-------|------------|-------|
| 8-12 | Wave 4: Opaque token + HMAC migration | Identity + teams |
| 10-14 | All services at Silver minimum | All teams |
| 12-18 | Gold tier push (incentivized, not mandated) | Ongoing |
| 14-18 | Legacy adapter sunset (HMAC, opaque tokens deprecated) | Identity team |
| 18 | Legacy auth methods disabled | Identity team |

### Staffing Estimate

| Role | Count | Duration |
|------|-------|----------|
| Identity Platform Engineers | 3-4 | Permanent (this is core infra) |
| SDK Engineers | 2 | 12 months (then maintenance mode) |
| Migration Support Engineers | 2-3 | 12 months (embedded with teams during waves) |
| Security/Compliance Specialist | 1 | Permanent |
| Developer Experience / Portal | 1 | 6 months build, then part-time |

---

## 9. Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Sidecar introduces latency | Bronze tier is passive (no blocking). Latency dashboard with SLA. Kill-switch to bypass sidecar. |
| Teams resist migration | Bronze tier requires zero effort. Incentive structure makes Gold attractive. Sunset timeline gives 18 months. |
| Token Exchange becomes SPOF | Deploy as regional cluster (3+ replicas). Sidecar caches exchange results. Fallback: accept original token with degraded trust_level. |
| Policy misconfiguration blocks traffic | Policy staging environment. Canary deployment for policy changes. "Dry run" mode evaluates but doesn't enforce. |
| Keycloak scalability at 500+ services | Keycloak clustering with realm-per-domain partitioning. Token Exchange caching reduces Keycloak load. Consider managed IdP (Okta/Auth0) if operational burden is too high. |
| Team doesn't want to own policy files | Provide sensible defaults. Identity team writes initial policy for each service based on observed traffic patterns (from Bronze telemetry). |

---

## 10. Success Metrics

| Metric | Baseline | 6-Month Target | 18-Month Target |
|--------|----------|----------------|-----------------|
| Services on Bronze+ | 0 | 300 (60%) | 500 (100%) |
| Services on Silver+ | 0 | 100 (20%) | 400 (80%) |
| Services on Gold | 0 | 30 (6%) | 200 (40%) |
| Auth-related incidents | TBD (measure now) | -50% | -90% |
| Audit prep time per team | ~2 weeks | < 3 days (Silver) | < 1 day (Silver+) |
| Mean auth latency overhead | 15-85ms (varies) | < 3ms (fabric services) | < 1ms (Gold services) |
| Secret rotation compliance | Manual/unknown | 90% automated | 100% automated |
| Cross-team integration time | 2-4 weeks | < 1 day (Bronze+) | < 1 hour (Gold) |
