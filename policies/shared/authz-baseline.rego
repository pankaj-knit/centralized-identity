package identity.authz

import rego.v1

default allow := false

# Allow if caller has the required role for the service+action
allow if {
	some role in input.roles
	role_permits(role, input.service_name, input.action)
}

# Allow if caller is the service itself (self-calls)
allow if {
	input.subject == sprintf("service:%s", [input.service_name])
}

# Role-to-permission mapping (loaded from external data in production)
role_permits(role, service, action) if {
	permission := data.permissions[role]
	some grant in permission.grants
	grant.service == service
	grant.action == action
}

role_permits(role, service, _) if {
	permission := data.permissions[role]
	some grant in permission.grants
	grant.service == service
	grant.action == "*"
}

# Trust level enforcement
deny[msg] if {
	input.trust_level == "low"
	input.action != "read"
	msg := "low trust tokens restricted to read-only operations"
}
