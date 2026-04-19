package identity.authz.order_service

import rego.v1

import data.identity.authz as baseline
import data.identity.pci as pci

default allow := false

# Inherit baseline authorization
allow if baseline.allow

# Order read: any authenticated user with order.read role
allow if {
	input.action == "read"
	some role in input.roles
	role == "order.read"
}

# Order write: requires medium+ trust and order.write role
allow if {
	input.action == "write"
	input.trust_level != "low"
	some role in input.roles
	role == "order.write"
}

# Payment-related order operations: PCI rules apply
deny[msg] if {
	input.resource == "order.payment"
	not pci.allow
	msg := "payment operations require PCI-compliant authentication"
}
