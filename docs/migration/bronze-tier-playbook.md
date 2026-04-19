# Bronze Tier Migration Playbook

## Overview

Bronze tier provides **zero-effort observability** for any service. The platform team deploys the identity sidecar in passive mode — no code changes, no team involvement required.

## What Teams Get

- **Auth traffic dashboard** — Who calls your service, with what identity, using what method
- **Cross-service interop** — Other teams can call your service via canonical token
- **Anomaly alerts** — Unusual callers, expired tokens being accepted, missing auth headers
- **Compliance report** — Auto-generated SOC2 access review evidence

## What Teams Do

**Nothing.** The platform team handles deployment.

## Latency Impact

**~0.5ms p99** — Sidecar observes traffic but does not block or validate.

## Deployment Steps (Platform Team)

### Kubernetes Services

1. **Label the namespace:**
   ```bash
   kubectl label namespace <team-ns> identity-fabric.io/inject=true
   ```

2. **Verify sidecar injection:**
   ```bash
   kubectl get pods -n <team-ns> -o jsonpath='{.items[*].spec.containers[*].name}' | tr ' ' '\n' | grep identity-sidecar
   ```

3. **Check telemetry flowing:**
   ```bash
   curl http://identity-sidecar:9090/metrics | grep identity_fabric_requests_total
   ```

### VM Services

1. **Run Ansible playbook:**
   ```bash
   ansible-playbook deploy-sdk-agent.yml -e "env=prod agent_mode=passive" -l <host-group>
   ```

2. **Verify agent is running:**
   ```bash
   systemctl status identity-agent
   journalctl -u identity-agent --since "5 minutes ago"
   ```

## Rollback

- **K8s:** Remove namespace label: `kubectl label namespace <team-ns> identity-fabric.io/inject-`
- **VM:** Stop agent: `systemctl stop identity-agent`

Rollback is instant. No service restart required on K8s (sidecar removal happens on next pod restart).

## Success Criteria

- [ ] Sidecar deployed alongside target services
- [ ] Telemetry visible in observability dashboard
- [ ] No latency regression >1ms p99
- [ ] Cross-service token exchange works for inbound calls

## Timeline

**1-2 days per team** (platform team work only).
