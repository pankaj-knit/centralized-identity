#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_DEV_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Identity Fabric Local Development Setup ==="
echo ""

# Check prerequisites
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "ERROR: $1 is required but not installed."
        exit 1
    fi
}

echo "Checking prerequisites..."
check_command docker
check_command curl
echo "  All prerequisites met."
echo ""

# Start infrastructure
echo "Starting infrastructure (Keycloak, Vault, OPA, Redis)..."
cd "$LOCAL_DEV_DIR"
docker compose up -d keycloak-db redis vault opa

echo "Waiting for database..."
until docker compose exec -T keycloak-db pg_isready -U keycloak 2>/dev/null; do
    sleep 2
done

echo "Starting Keycloak..."
docker compose up -d keycloak

echo "Waiting for Keycloak to be ready..."
until curl -sf http://localhost:8443/health/ready 2>/dev/null; do
    sleep 5
done
echo "  Keycloak ready at http://localhost:8443 (admin/admin)"

echo "Waiting for Vault to be ready..."
until curl -sf http://localhost:8200/v1/sys/health 2>/dev/null; do
    sleep 2
done
echo "  Vault ready at http://localhost:8200 (token: root)"

echo "Waiting for OPA to be ready..."
until curl -sf http://localhost:8181/health 2>/dev/null; do
    sleep 2
done
echo "  OPA ready at http://localhost:8181"

# Start mock services
echo ""
echo "Starting mock legacy services..."
docker compose up -d legacy-jwt-app opaque-token-app saml-app keycloak-app

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Services:"
echo "  Keycloak:         http://localhost:8443   (admin/admin)"
echo "  Vault:            http://localhost:8200   (token: root)"
echo "  OPA:              http://localhost:8181"
echo "  Token Exchange:   http://localhost:8080   (build first: docker compose up -d token-exchange)"
echo ""
echo "Mock Legacy Services:"
echo "  Legacy JWT App:   http://localhost:9001/issue-token"
echo "  Opaque Token App: http://localhost:9002/login"
echo "  SAML App:         http://localhost:9003/issue-assertion"
echo "  Keycloak App:     http://localhost:9004"
echo ""
echo "Try it:"
echo "  # Get a legacy JWT"
echo "  curl http://localhost:9001/issue-token | jq"
echo ""
echo "  # Get an opaque session token"
echo "  curl -X POST http://localhost:9002/login | jq"
echo ""
echo "  # Get a SAML assertion"
echo "  curl http://localhost:9003/issue-assertion | jq"
echo ""
echo "  # Get a Keycloak OIDC token"
echo "  curl -X POST http://localhost:8443/realms/identity-fabric/protocol/openid-connect/token \\"
echo "    -d 'grant_type=password&client_id=sample-app&username=test-user&password=test' | jq"
