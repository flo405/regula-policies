package rules.sg_private_ingress_only

__rego__metadoc__ := {
  "id": "EXO-0003",
  "title": "Security group rules must only allow traffic from private networks or Cloudflare",
  "description": "Security group rules must only allow ingress traffic from IP addresses within 10.0.0.0/8 or 192.168.0.0/16 on all ports or Cloudflare's public IPs only on port 443.",
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

allow {
  (input.type) == "ingress"
  startswith(input.cidr, "192.168.") == true
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "173.245.48.0/20"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "103.21.244.0/22"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "103.22.200.0/22"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "103.31.4.0/22"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "141.101.64.0/18"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "108.162.192.0/18"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "190.93.240.0/20"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "188.114.96.0/20"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "197.234.240.0/22"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "198.41.128.0/17"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "162.158.0.0/15"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "104.16.0.0/13"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "104.24.0.0/14"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "172.64.0.0/13"
}

allow {
  lower(input.type) == "ingress"
  input.start_port == 443
  input.end_port == 443
  input.cidr == "131.0.72.0/22"
}
