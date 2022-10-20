package rules.compute_zone_at_vie_1

__rego__metadoc__ := {
  "id": "EXO-0005",
  "title": "All compute instances must be deployed in Austria.",
  "description": "To comply with data protection requirementsm, we only deploy VMs in the datacenter in Vienna, Austria.",
  "custom": {
    "controls": {
      "CORPORATE-POLICY": [
        "DATA_PROTECTION_POLICY_4.17"
      ]
    },
    "severity": "High"
  }
}

resource_type = "exoscale_compute_instance"

default allow = false

allow {
  input.zone == "at-vie-1"
}
