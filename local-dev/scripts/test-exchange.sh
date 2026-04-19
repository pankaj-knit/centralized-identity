#!/usr/bin/env bash
set -euo pipefail

echo "=== Token Exchange Integration Test ==="
echo ""

TES_URL="${TES_URL:-http://localhost:8080}"

# Test 1: Exchange a legacy JWT
echo "--- Test 1: Legacy JWT → Canonical Token ---"
LEGACY_JWT=$(curl -s http://localhost:9001/issue-token | jq -r '.token')
echo "  Legacy JWT: ${LEGACY_JWT:0:50}..."

RESULT=$(curl -s -X POST "$TES_URL/v1/token/exchange" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\": \"$LEGACY_JWT\",
    \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\"
  }")

echo "  Result: $(echo "$RESULT" | jq -c '.')"
echo ""

# Test 2: Exchange an opaque session token
echo "--- Test 2: Opaque Token → Canonical Token ---"
SESSION=$(curl -s -X POST http://localhost:9002/login | jq -r '.session_token')
echo "  Session token: ${SESSION:0:30}..."

RESULT=$(curl -s -X POST "$TES_URL/v1/token/exchange" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\": \"$SESSION\",
    \"subject_token_type\": \"urn:identity-fabric:token-type:opaque\"
  }")

echo "  Result: $(echo "$RESULT" | jq -c '.')"
echo ""

# Test 3: Exchange a SAML assertion
echo "--- Test 3: SAML Assertion → Canonical Token ---"
SAML=$(curl -s http://localhost:9003/issue-assertion | jq -r '.saml_assertion')
echo "  SAML assertion: ${SAML:0:50}..."

RESULT=$(curl -s -X POST "$TES_URL/v1/token/exchange" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\": \"$SAML\",
    \"subject_token_type\": \"urn:ietf:params:oauth:token-type:saml2\"
  }")

echo "  Result: $(echo "$RESULT" | jq -c '.')"
echo ""

# Test 4: Health check
echo "--- Test 4: Health Check ---"
echo "  Health: $(curl -s "$TES_URL/healthz")"
echo "  Ready:  $(curl -s "$TES_URL/readyz")"
echo ""

echo "=== All Tests Complete ==="
