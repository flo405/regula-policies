package rules.sg_no_port_ranges

__rego__metadoc__ := {
  "id": "EXO-0002",
  "title": "A single security group rule must not cover more than one port",
  "description": "Following the security group rules must be as granular as possible.",
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
  input.start_port == input.end_port
}
