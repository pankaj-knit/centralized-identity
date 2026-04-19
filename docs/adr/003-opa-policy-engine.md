# ADR-003: OPA as Policy Decision Point

**Status:** Accepted
**Date:** 2026-04-17
**Deciders:** Identity Infrastructure Team, Security

## Context

Authorization logic is currently embedded in each service — scattered across code, config files, and database tables. This makes auditing impossible, policy changes require code deploys, and there's no way to enforce org-wide security baselines (PCI-DSS, SOC2).

## Decision

Adopt **Open Policy Agent (OPA)** with Rego as the policy language for all authorization decisions.

**Architecture:**
- Policies stored in Git (policy-as-code, versioned, reviewed)
- Identity team owns `policies/shared/` (org-wide baselines, non-overridable)
- Service teams own `policies/examples/<service>/` (service-specific rules)
- OPA deployed in three modes based on latency requirements:
  1. **Embedded WASM** — Compiled Rego in sidecar/SDK, <0.1ms
  2. **Sidecar daemon** — Localhost gRPC, <1ms
  3. **Central cluster** — Network call, 2-5ms (batch jobs)

**Policy hierarchy:**
```
shared/pci-baseline.rego      ← Identity team (cannot override)
shared/soc2-baseline.rego     ← Identity team (cannot override)
shared/authz-baseline.rego    ← Identity team (defaults, overridable)
examples/<service>/authz.rego ← Service team (extends baseline)
```

## Alternatives Considered

1. **AWS Cedar** — Strong typing, better for relationship-based access. But younger ecosystem, less tooling, fewer deployment modes.
2. **Casbin** — Simpler model (RBAC/ABAC). But lacks the expressiveness for PCI-scoped conditional policies.
3. **Custom policy service** — Maximum flexibility. But high build/maintain cost, no ecosystem benefits.

## Consequences

- Teams must learn Rego (mitigated by templates, examples, and self-service testing portal)
- Policy changes deploy independently of service code (faster iteration, decoupled releases)
- Audit trail: every policy version, every evaluation, fully traceable for SOC2/PCI
- Org-wide baselines (PCI, SOC2) enforced automatically — teams can't accidentally weaken security
