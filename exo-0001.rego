package rules.sg_no_public_ingress

__rego__metadoc__ := {
  "id": "EXO-0001",
  "title": "Security group rules must not allow traffic from 0.0.0.0/0",
  "description": "Security group rules must not allow ingress traffic from 0.0.0.0/0",
  "custom": {
    "controls": {
      "CORPORATE-POLICY": [
        "CLOUD_SECURITY_POLICY_1.1"
      ]
    },
    "severity": "High"
  }
}

resource_type = "exoscale_security_group_rule"

default allow = false

allow {
  lower(input.type) == "egress"
}

allow {
  lower(input.type) == "ingress"
  input.cidr != "0.0.0.0/0"
}
