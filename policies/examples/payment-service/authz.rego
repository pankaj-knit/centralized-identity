package identity.authz.payment_service

import rego.v1

import data.identity.pci as pci

default allow := false

# Payment service requires PCI compliance for all operations
allow if {
	pci.allow
	has_payment_role
}

has_payment_role if {
	some role in input.roles
	startswith(role, "payment.")
}

# All payment operations are write-equivalent from a trust perspective
deny[msg] if {
	input.trust_level != "high"
	msg := "payment service requires high trust authentication"
}

deny[msg] if {
	input.auth_method == "legacy"
	msg := "legacy auth methods not permitted for payment service"
}
