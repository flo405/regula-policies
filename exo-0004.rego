package rules.sg_private_ingress_only

__rego__metadoc__ := {
  "id": "EXO-0004",
  "title": "Security group rules must only allow traffic from private networks or Cloudflare",
  "description": "Security group rules must only allow ingress traffic from IP addresses within 10.0.0.0/8 on all ports or Cloudflare's public IPs only on port 443.",
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
  startswith(input.cidr, "10.") == true
}

