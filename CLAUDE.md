# Identity Fabric - Project Instructions

## Project Overview

Unified identity infrastructure platform consolidating fragmented auth (custom JWTs, opaque tokens, HMAC blobs, SAML, mTLS) into a single Identity Fabric with tiered adoption (Bronze/Silver/Gold).

## Tech Stack

- **Language:** Go 1.22+
- **IdP:** Keycloak (official, OIDC)
- **Secrets:** HashiCorp Vault
- **Policy:** OPA (Open Policy Agent) with Rego
- **Deploy:** K8s + Helm, Terraform, Docker Compose, Ansible
- **Observability:** OpenTelemetry

## Architecture

- `services/` — Go microservices (token-exchange, policy-engine, control-plane, credential-manager)
- `sdk/go/` — Client SDK for service teams (one-line init)
- `sidecar/` — Identity sidecar proxy for K8s
- `policies/` — OPA Rego policies (shared baselines + per-service)
- `deploy/` — Kubernetes Helm charts, Terraform modules, Ansible playbooks
- `local-dev/` — Docker Compose full stack with mock legacy services

## Conventions

- Each Go service is a separate module under `services/<name>/`
- Internal packages under `internal/` — not exported
- Public SDK API under `sdk/go/` — exported, minimal surface area
- OPA policies in `policies/shared/` are org-wide baselines (non-overridable)
- OPA policies in `policies/examples/` are per-service templates
- ADRs in `docs/adr/` follow `NNN-title.md` format
- All API endpoints versioned: `/v1/...`

## Build & Test

```bash
# Run all tests
go test ./...

# Run integration tests (needs local-dev stack)
cd local-dev && docker compose up -d
go test -tags=integration ./tests/integration/...

# Format
gofmt -w .

# Lint
golangci-lint run ./...
```

## Key Design Decisions

- Token Exchange implements RFC 8693 (OAuth 2.0 Token Exchange)
- Canonical token is a short-lived JWT (5 min default, 60s for PCI CDE)
- Policy evaluation is local-first (embedded OPA WASM or localhost gRPC)
- Sidecar is the default on K8s; SDK for VMs/serverless/latency-critical
- Bronze tier requires zero team effort (platform team deploys passively)

## graphify

This project has a graphify-rs knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `graphify-rs build --path . --output graphify-out --no-llm --update` to keep the graph current (fast, AST-only, ~2-5s)
