# Silver Tier Migration Playbook

## Overview

Silver tier adds **active authorization** via policy-as-code. Teams move their authZ logic from application code into OPA/Rego policies. The sidecar switches from passive to active mode.

## Prerequisites

- Service is already at Bronze tier (sidecar deployed, telemetry flowing)
- Team has reviewed Bronze telemetry to understand current auth patterns

## What Teams Get

- **Policy-as-code authorization** — Define access rules in Rego, deploy independently of service code
- **Automatic credential rotation** — Vault-managed secrets, no manual rotation
- **PCI-DSS compliance reports** — Per-endpoint evidence auto-generated
- **Self-service policy testing** — "Will this request be allowed?" portal

## What Teams Do

1. Write OPA policies for their service (1-2 sprint effort)
2. Test policies in staging
3. Switch sidecar from passive to active mode
4. Remove authZ code from application (optional but recommended)

## Latency Impact

**~1ms p99** — Local policy evaluation replaces application-level DB lookups. Often *faster* than current implementation.

## Step-by-Step Migration

### Step 1: Understand Current Auth Patterns (Day 1-2)

Review Bronze tier telemetry:
```bash
# See who calls your service and how
curl "http://control-plane:8090/api/v1/services/<service-name>/auth-report"
```

Identify:
- Which endpoints require authentication
- Which roles/permissions are checked
- What token types are currently accepted

### Step 2: Write OPA Policies (Sprint 1)

Start from the template:
```bash
cp policies/examples/order-service/authz.rego policies/<your-service>/authz.rego
```

Define your access rules:
```rego
package identity.authz.<your_service>

import rego.v1
import data.identity.authz as baseline

default allow := false

# Your service-specific rules here
allow if {
    input.action == "read"
    some role in input.roles
    role == "<your-service>.read"
}
```

### Step 3: Test Policies (Sprint 1)

Use the policy testing portal:
```bash
# Test a specific request against your policy
curl -X POST http://control-plane:8090/api/v1/policy-test \
  -d '{
    "policy_path": "identity/authz/<your_service>",
    "input": {
      "subject": "user:test-user",
      "roles": ["<your-service>.read"],
      "action": "read",
      "trust_level": "high"
    }
  }'
```

Run policy unit tests:
```bash
opa test policies/<your-service>/ policies/shared/ -v
```

### Step 4: Deploy to Staging (Sprint 2)

1. Push policies to Git (triggers automated deployment to OPA)
2. Switch sidecar to active mode in staging:
   ```yaml
   # Add annotation to deployment
   identity-fabric.io/mode: "active"
   ```
3. Monitor for 1 week — check for false denials in dashboard

### Step 5: Deploy to Production (Sprint 2)

1. Enable active mode with **dry-run first**:
   ```yaml
   identity-fabric.io/mode: "active"
   identity-fabric.io/enforce: "false"  # Log-only, don't block
   ```
2. Monitor for 3-5 days — verify no legitimate traffic would be blocked
3. Enable enforcement:
   ```yaml
   identity-fabric.io/enforce: "true"
   ```

### Step 6: Remove Legacy AuthZ Code (Optional)

Once active mode is enforced, the application's authZ code is redundant. Teams can:
- Remove in-app role checks, ACL code, and permission DB lookups
- Simplify request handlers to assume the sidecar already authorized the call
- Delete related tests that tested in-app authorization logic

## Rollback

1. **Instant:** Switch sidecar back to passive mode:
   ```yaml
   identity-fabric.io/mode: "passive"
   ```
2. Application's existing authZ code (if not yet removed) takes over immediately

## Success Criteria

- [ ] OPA policies defined and tested for all endpoints
- [ ] Sidecar in active/enforce mode in production
- [ ] Zero false denials for 7 consecutive days
- [ ] Compliance report auto-generated from policy decisions
- [ ] Credential rotation automated via Vault

## Timeline

**1-2 sprints** (2-4 weeks), primarily team effort with identity team support.
