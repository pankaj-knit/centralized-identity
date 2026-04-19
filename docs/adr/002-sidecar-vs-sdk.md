# ADR-002: Sidecar vs SDK Deployment Strategy

**Status:** Accepted
**Date:** 2026-04-17
**Deciders:** Identity Infrastructure Team, Platform Engineering

## Context

We need to deploy the identity data plane (token validation, policy evaluation, telemetry) alongside 500+ services running on K8s, VMs, and serverless. A single deployment model won't fit all environments.

## Decision

Adopt a **dual-track strategy**: sidecar as default on K8s, SDK for VMs/serverless/latency-critical paths.

| Environment | Default | Override |
|-------------|---------|----------|
| Kubernetes | Sidecar (mutating webhook injection) | SDK for <1ms budget |
| VMs | SDK agent (systemd service) | Sidecar via VM agent |
| Serverless | SDK library | N/A |
| Batch/Cron | SDK library | Central PDP call |

**Sidecar** runs as a localhost proxy:
- Intercepts HTTP/gRPC traffic
- Validates tokens, evaluates policy, reports telemetry
- Deployed by platform team via admission controller — zero team effort
- Supports passive (Bronze) and active (Silver) modes

**SDK** is an embedded Go library:
- Middleware for HTTP/gRPC frameworks
- Same logic as sidecar, different packaging
- Sub-millisecond overhead (no proxy hop)
- Team integrates into their code (Gold tier)

Both share the same core logic (token validation, policy evaluation, JWKS cache). The sidecar wraps the SDK in a proxy.

## Alternatives Considered

1. **Sidecar only** — Won't work for VMs and serverless. Forces proxy overhead on latency-critical services.
2. **SDK only** — Requires code changes from every team. Can't achieve Bronze tier (zero effort).
3. **Service mesh integration only (Istio)** — Mesh is partially deployed. Would create a hard dependency on mesh adoption for identity. Identity concerns should be application-layer, not transport-layer.

## Consequences

- Platform team maintains two artifacts (sidecar binary + SDK library) with shared core
- Bronze tier is achievable only via sidecar (passive mode)
- Gold tier requires SDK integration (but sidecar can remain as a fallback)
- Latency SLA differs by deployment mode: sidecar <2ms p99, SDK <1ms p99
