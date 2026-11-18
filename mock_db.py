"""In-memory compliance state used by the hackathon API."""

from copy import deepcopy


COMPLIANCE_STATE = {
    "company": "FintechX",
    "data_retention_days": 30,
    "encryption": "AES-128",
    "active_jurisdictions": ["CA", "TX"],
}


def get_compliance_state():
    """Return a copy so request handlers cannot mutate the mock database."""
    return deepcopy(COMPLIANCE_STATE)
