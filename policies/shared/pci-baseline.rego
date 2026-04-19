package identity.pci

import rego.v1

default allow := false

# PCI CDE access requires high trust level authentication
allow if {
	input.trust_level == "high"
	input.pci_scope == true
	valid_auth_method
}

valid_auth_method if input.auth_method == "oidc"
valid_auth_method if input.auth_method == "mtls"

# HMAC and legacy tokens cannot access PCI-scoped resources
deny[msg] if {
	input.pci_scope == true
	input.auth_method == "legacy"
	msg := "legacy auth methods cannot access PCI-scoped resources"
}

deny[msg] if {
	input.pci_scope == true
	input.trust_level != "high"
	msg := sprintf("PCI access requires high trust, got: %s", [input.trust_level])
}

# Audit logging is mandatory for all PCI decisions
audit_required := true
