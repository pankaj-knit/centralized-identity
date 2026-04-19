# Identity Fabric

Unified identity infrastructure for standardizing authentication and authorization across 500+ services.

## Problem

Fragmented identity landscape: custom JWTs, opaque session tokens, HMAC-signed blobs, SAML, mTLS, and partial Keycloak adoption. Each team implements auth differently, creating compliance burden, integration friction, and inconsistent security posture.

## Solution

An **Identity Fabric** — an abstraction layer that speaks every protocol today and gradually converges teams onto a unified OIDC standard, without blocking business releases.

### Architecture

```
┌────────────────────────────────────────────┐
│           Identity Control Plane            │
│  Policy Admin | Key Mgmt | Observability   │
└──────────────────┬─────────────────────────┘
                   │
     ┌─────────────┼─────────────┐
     │             │             │
 Token          Policy       Credential
 Exchange       Decision     Lifecycle
 Service        Point        Manager
 (RFC 8693)     (OPA)        (Vault+KC)
     │             │             │
     └─────────────┼─────────────┘
                   │
        Identity Data Plane
        (Sidecar / SDK)
```

### Core Components

| Component | Purpose | Port |
|-----------|---------|------|
| **Token Exchange Service** | Accepts any token format, emits canonical JWT | 8080 |
| **Policy Engine** | OPA-based authorization, embedded or sidecar | 8181 |
| **Control Plane** | Service registry, migration tracker, dashboard | 8090 |
| **Credential Manager** | Vault + Keycloak lifecycle management | 8070 |

### Adoption Tiers

| Tier | Team Effort | What You Get |
|------|-------------|-------------|
| **Bronze** | Zero | Observability, cross-service interop, compliance reports |
| **Silver** | 1-2 sprints | Policy-as-code authZ, auto credential rotation, audit-ready |
| **Gold** | 2-4 sprints | Sub-ms auth, zero-touch security upgrades, reduced on-call |

## Quick Start

### Local Development

```bash
# Start the full local stack (Keycloak, Vault, OPA, all services, mock legacy apps)
cd local-dev
docker compose up -d

# Keycloak admin:   http://localhost:8443   (admin/admin)
# Vault UI:         http://localhost:8200   (token: root)
# OPA playground:   http://localhost:8181
# Control Plane:    http://localhost:8090
# Token Exchange:   http://localhost:8080
```

### Test a Token Exchange

```bash
# Exchange a legacy custom JWT for a canonical token
curl -X POST http://localhost:8080/v1/token/exchange \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<your-legacy-jwt>",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
  }'
```

### Run Tests

```bash
# Unit tests
go test ./...

# Integration tests (requires local stack running)
go test -tags=integration ./tests/integration/...

# Load tests
cd tests/load && k6 run token-exchange-load.js
```

## Project Structure

```
.
├── docs/                          # Architecture, ADRs, migration playbooks
│   ├── architecture/              # System design documents
│   ├── adr/                       # Architecture Decision Records
│   ├── migration/                 # Tier migration playbooks
│   └── runbooks/                  # Operational runbooks
├── services/                      # Backend services (Go)
│   ├── token-exchange/            # Token Exchange Service (RFC 8693)
│   ├── policy-engine/             # OPA-based Policy Decision Point
│   ├── control-plane/             # Registry, dashboard, migration tracker
│   └── credential-manager/        # Vault + Keycloak lifecycle
├── sdk/                           # Client SDKs
│   ├── go/                        # Go SDK (primary)
│   ├── java/                      # Java SDK
│   ├── python/                    # Python SDK
│   └── node/                      # Node.js SDK
├── sidecar/                       # Identity sidecar proxy
├── policies/                      # OPA/Rego policies
│   ├── shared/                    # Org-wide baseline policies
│   └── examples/                  # Per-service policy examples
├── deploy/                        # Deployment manifests
│   ├── kubernetes/helm/           # Helm charts
│   ├── terraform/                 # IaC for cloud resources
│   ├── docker-compose/            # Container orchestration
│   └── ansible/                   # VM deployment playbooks
├── local-dev/                     # Local development environment
│   ├── mock-services/             # Legacy token mock apps
│   ├── config/                    # Keycloak, Vault, OPA config
│   └── scripts/                   # Setup and test scripts
├── tests/                         # Integration, E2E, load tests
└── tools/                         # Migration tracker, policy tester
```

## Documentation

- [Architecture Design](docs/architecture/identity-fabric-design.md) — Full system design
- [ADR-001: Canonical Token Format](docs/adr/001-canonical-token-format.md)
- [ADR-002: Sidecar vs SDK Strategy](docs/adr/002-sidecar-vs-sdk.md)
- [ADR-003: OPA for Policy Engine](docs/adr/003-opa-policy-engine.md)
- [Bronze Tier Playbook](docs/migration/bronze-tier-playbook.md)
- [Silver Tier Playbook](docs/migration/silver-tier-playbook.md)
- [Gold Tier Playbook](docs/migration/gold-tier-playbook.md)

## Tech Stack

- **Language:** Go 1.22+
- **IdP:** Keycloak 24+
- **Secrets:** HashiCorp Vault
- **Policy Engine:** Open Policy Agent (OPA)
- **Deployment:** Kubernetes, Helm, Terraform, Ansible
- **Observability:** OpenTelemetry, Prometheus, Grafana
