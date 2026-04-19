package identity.soc2

import rego.v1

# SOC2 baseline: every access decision must be auditable
audit_required := true

# All service-to-service calls must have an authenticated identity
default authenticated := false

authenticated if {
	input.subject != ""
	input.auth_method != ""
}

deny[msg] if {
	not authenticated
	msg := "unauthenticated access violates SOC2 requirements"
}

# Role-based access must be explicitly granted
default has_required_role := false

has_required_role if {
	some role in input.roles
	role == input.required_role
}

# Trust level must be at least medium for any write operation
deny[msg] if {
	input.action == "write"
	input.trust_level == "low"
	msg := "low trust level cannot perform write operations"
}

deny[msg] if {
	input.action == "delete"
	input.trust_level == "low"
	msg := "low trust level cannot perform delete operations"
}
