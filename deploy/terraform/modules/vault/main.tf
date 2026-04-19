variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
}

variable "vault_namespace" {
  type    = string
  default = "identity-fabric"
}

variable "kms_key_id" {
  type        = string
  description = "KMS key for Vault auto-unseal"
}

resource "kubernetes_namespace" "vault" {
  metadata {
    name = var.vault_namespace
    labels = {
      "identity-fabric.io/component" = "vault"
      "environment"                   = var.environment
    }
  }
}

resource "helm_release" "vault" {
  name       = "vault"
  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = "0.27.0"
  namespace  = kubernetes_namespace.vault.metadata[0].name

  values = [
    yamlencode({
      server = {
        ha = {
          enabled  = true
          replicas = var.environment == "prod" ? 5 : 3
          raft = {
            enabled = true
          }
        }
        seal = {
          awskms = {
            region     = data.aws_region.current.name
            kms_key_id = var.kms_key_id
          }
        }
        resources = {
          requests = {
            cpu    = "250m"
            memory = "256Mi"
          }
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }
        auditStorage = {
          enabled = true
          size    = "10Gi"
        }
      }
      injector = {
        enabled = true
      }
    })
  ]
}

data "aws_region" "current" {}

# PKI secrets engine for mTLS certificates
resource "vault_mount" "pki" {
  path                  = "identity-fabric/pki"
  type                  = "pki"
  max_lease_ttl_seconds = 87600 * 3600 # 10 years for root CA
}

# Transit secrets engine for token signing keys
resource "vault_mount" "transit" {
  path = "identity-fabric/transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "token_signing" {
  backend          = vault_mount.transit.path
  name             = "canonical-token-signing"
  type             = "ecdsa-p256"
  deletion_allowed = false
  exportable       = false
  min_encryption_version = 1
  min_decryption_version = 1
}

# KV secrets engine for HMAC shared secrets (migration period)
resource "vault_mount" "kv" {
  path = "identity-fabric/kv"
  type = "kv-v2"
}

output "vault_namespace" {
  value = kubernetes_namespace.vault.metadata[0].name
}

output "transit_path" {
  value = vault_mount.transit.path
}

output "pki_path" {
  value = vault_mount.pki.path
}
