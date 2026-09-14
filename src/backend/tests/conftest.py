"""
Shared pytest fixtures for D2 Threat Intelligence backend tests.
"""

import sys
import os
import uuid
from datetime import datetime

# ---------------------------------------------------------------------------
# Ensure the backend directory is on sys.path so all modules can be imported
# when pytest is run from inside d2-threat-intel/backend/.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest


# ---------------------------------------------------------------------------
# Reference-data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_safe_ips():
    """A small set of known-safe IP addresses used in FP classification tests."""
    return ["10.0.0.50", "10.0.0.51", "45.33.32.156"]


@pytest.fixture
def sample_mitre_mapping():
    """A minimal subset of the MITRE ATT&CK mapping covering the most-tested types."""
    return {
        "brute_force": [
            {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"}
        ],
        "malware": [
            {"id": "T1204", "name": "User Execution", "tactic": "execution"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
        ],
        "recon": [
            {"id": "T1595", "name": "Active Scanning", "tactic": "reconnaissance"}
        ],
        "lateral_movement": [
            {"id": "T1021", "name": "Remote Services", "tactic": "lateral-movement"}
        ],
    }


# ---------------------------------------------------------------------------
# Raw-alert factory fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def raw_alert_factory():
    """Return a callable that builds a minimal valid raw alert dict.

    Call it with keyword overrides to customise individual fields::

        alert = raw_alert_factory(source_ip="1.2.3.4", alert_type="malware")
    """
    def _factory(**overrides):
        base = {
            "id": str(uuid.uuid4()),
            "source": "SIEM-Alpha",
            "format": "siem",
            "timestamp": "2026-01-15T08:00:00Z",
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "alert_type": "brute_force",
            "description": "Multiple failed login attempts detected.",
            "severity": "high",
            "confidence": 0.8,
            "extra": {"attempts": 50},
        }
        base.update(overrides)
        return base

    return _factory


# ---------------------------------------------------------------------------
# Normalised-alert factory fixture
# (mirrors the output of normalise() for use in downstream pipeline tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def normalised_alert_factory():
    """Return a callable that builds a minimal normalised alert dict."""
    def _factory(**overrides):
        base = {
            "id": str(uuid.uuid4()),
            "raw_source": "SIEM-Alpha",
            "source_format": "siem",
            "timestamp": datetime(2026, 1, 15, 8, 0, 0),
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "alert_type": "brute_force",
            "description": "Multiple failed login attempts detected.",
            "severity_raw": "high",
            "confidence": 0.8,
            "is_false_positive": False,
            "fp_reason": None,
            "incident_id": None,
            "extra_data": None,
            "created_at": datetime.utcnow(),
        }
        base.update(overrides)
        return base

    return _factory
