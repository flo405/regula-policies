package rules.sg_22_jump_host

__rego__metadoc__ := {
  "id": "EXO-0004",
  "title": "Security group rules must allow traffic to port 22 only from jump host",
  "description": "Security group rules must only allow ingress traffic to port 22 from 10.0.1.10/32",
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

default allow = true

deny {
  lower(input.type) == "ingress"
  input.start_port == 22
  input.end_port == 22
  input.cidr != "10.0.1.10/32"
}



