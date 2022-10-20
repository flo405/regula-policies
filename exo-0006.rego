package rules.compute_label_dataclass

__rego__metadoc__ := {
  "id": "EXO-0006",
  "title": "All compute instances must have a data classification label.",
  "description": "To identify resources correctly, a dataclass label must be set to public, internal, confidential or secret.",
  "custom": {
    "controls": {
      "CORPORATE-POLICY": [
        "DATA_PROTECTION_POLICY_4.17"
      ]
    },
    "severity": "Medium"
  }
}

resource_type = "exoscale_compute_instance"

default allow = false

allow {
input.labels["dataclass"] == "public"
}

allow {
input.labels["dataclass"] == "internal"
}

allow {
input.labels["dataclass"] == "confidential"
}

allow {
input.labels["dataclass"] == "secret"
}