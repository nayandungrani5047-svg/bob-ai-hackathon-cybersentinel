"""
Unit tests for pipeline/correlator.py
"""

import uuid
from datetime import datetime, timedelta

import pytest

from pipeline.correlator import correlate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert(
    alert_id: str = None,
    source_ip: str = "192.168.1.100",
    dest_ip: str = "10.0.0.5",
    alert_type: str = "brute_force",
    severity_raw: str = "high",
    confidence: float = 0.8,
    timestamp: datetime = None,
    is_false_positive: bool = False,
):
    """Build a minimal normalised+classified alert dict."""
    return {
        "id": alert_id or str(uuid.uuid4()),
        "raw_source": "SIEM-Alpha",
        "source_format": "siem",
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "alert_type": alert_type,
        "description": "Test alert",
        "severity_raw": severity_raw,
        "confidence": confidence,
        "timestamp": timestamp or datetime(2026, 1, 15, 8, 0, 0),
        "is_false_positive": is_false_positive,
        "fp_reason": None,
        "incident_id": None,
    }


BASE_TIME = datetime(2026, 1, 15, 8, 0, 0)


# ---------------------------------------------------------------------------
# Rule 1 — Attack-chain pattern
# ---------------------------------------------------------------------------

class TestAttackChainRule:

    def test_attack_chain_creates_incident(self):
        """Three alerts from same IP covering recon → brute_force → malware
        within 1 hour should produce exactly 1 incident with rule 'attack_chain'."""
        alerts = [
            _alert(alert_id="a1", source_ip="5.5.5.5", alert_type="recon",
                   timestamp=BASE_TIME),
            _alert(alert_id="a2", source_ip="5.5.5.5", alert_type="brute_force",
                   timestamp=BASE_TIME + timedelta(minutes=20)),
            _alert(alert_id="a3", source_ip="5.5.5.5", alert_type="malware",
                   timestamp=BASE_TIME + timedelta(minutes=40)),
        ]
        incidents = correlate(alerts)

        chain_incidents = [i for i in incidents if i["correlation_rule"] == "attack_chain"]
        assert len(chain_incidents) == 1, (
            f"Expected 1 attack_chain incident, got {len(chain_incidents)}: "
            f"{[i['correlation_rule'] for i in incidents]}"
        )
        assert set(chain_incidents[0]["alert_ids"]) == {"a1", "a2", "a3"}

    def test_attack_chain_requires_3_stages(self):
        """Only 2 chain stages from the same IP should NOT produce an attack_chain incident."""
        alerts = [
            _alert(alert_id="b1", source_ip="6.6.6.6", alert_type="recon",
                   timestamp=BASE_TIME),
            _alert(alert_id="b2", source_ip="6.6.6.6", alert_type="brute_force",
                   timestamp=BASE_TIME + timedelta(minutes=10)),
        ]
        incidents = correlate(alerts)

        chain_incidents = [i for i in incidents if i["correlation_rule"] == "attack_chain"]
        assert len(chain_incidents) == 0

    def test_returns_correct_alert_ids_in_chain(self):
        """Incident alert_ids should contain exactly the IDs of the correlated alerts."""
        a1_id = "chain-a1"
        a2_id = "chain-a2"
        a3_id = "chain-a3"

        alerts = [
            _alert(alert_id=a1_id, source_ip="7.7.7.7", alert_type="recon",
                   timestamp=BASE_TIME),
            _alert(alert_id=a2_id, source_ip="7.7.7.7", alert_type="brute_force",
                   timestamp=BASE_TIME + timedelta(minutes=15)),
            _alert(alert_id=a3_id, source_ip="7.7.7.7", alert_type="lateral_movement",
                   timestamp=BASE_TIME + timedelta(minutes=30)),
        ]
        incidents = correlate(alerts)

        chain = next(i for i in incidents if i["correlation_rule"] == "attack_chain")
        assert set(chain["alert_ids"]) == {a1_id, a2_id, a3_id}


# ---------------------------------------------------------------------------
# Rule 2 — Same-IP time window
# ---------------------------------------------------------------------------

class TestSameIPWindowRule:

    def test_same_ip_window_creates_incident(self):
        """Two brute_force alerts from the same IP 10 minutes apart → 1 incident
        with rule 'same_ip_window'."""
        alerts = [
            _alert(alert_id="w1", source_ip="8.8.8.8", alert_type="brute_force",
                   timestamp=BASE_TIME),
            _alert(alert_id="w2", source_ip="8.8.8.8", alert_type="brute_force",
                   timestamp=BASE_TIME + timedelta(minutes=10)),
        ]
        incidents = correlate(alerts)

        window_incidents = [i for i in incidents if i["correlation_rule"] == "same_ip_window"]
        assert len(window_incidents) == 1
        assert set(window_incidents[0]["alert_ids"]) == {"w1", "w2"}

    def test_same_ip_outside_window_not_correlated(self):
        """Two alerts from the same IP more than 30 minutes apart should NOT be
        combined into a same_ip_window incident."""
        alerts = [
            _alert(alert_id="ow1", source_ip="9.9.9.9", alert_type="brute_force",
                   timestamp=BASE_TIME),
            _alert(alert_id="ow2", source_ip="9.9.9.9", alert_type="brute_force",
                   timestamp=BASE_TIME + timedelta(minutes=45)),
        ]
        incidents = correlate(alerts)

        window_incidents = [i for i in incidents if i["correlation_rule"] == "same_ip_window"]
        assert len(window_incidents) == 0


# ---------------------------------------------------------------------------
# Rule 4 — Singleton fallback
# ---------------------------------------------------------------------------

class TestSingletonRule:

    def test_singleton_fallback(self):
        """A single genuine alert with no correlation candidates → 1 singleton incident."""
        alerts = [
            _alert(alert_id="s1", source_ip="11.11.11.11", alert_type="phishing",
                   timestamp=BASE_TIME),
        ]
        incidents = correlate(alerts)

        assert len(incidents) == 1
        assert incidents[0]["correlation_rule"] == "singleton"
        assert incidents[0]["alert_ids"] == ["s1"]

    def test_singleton_has_correct_structure(self):
        """Singleton incident should have expected keys."""
        alerts = [_alert(alert_id="s2", source_ip="12.12.12.12")]
        incidents = correlate(alerts)

        inc = incidents[0]
        for key in ("id", "title", "alert_ids", "correlation_rule", "source_ips"):
            assert key in inc, f"Missing key: {key}"

    def test_multiple_unrelated_alerts_become_singletons(self):
        """Three alerts from completely different IPs with no shared dest_ip
        and types that don't form a chain → 3 singleton incidents."""
        alerts = [
            # Use dest_ip=None to avoid accidental dest_cluster grouping
            _alert(alert_id="m1", source_ip="1.1.1.1", dest_ip=None, alert_type="phishing",
                   timestamp=BASE_TIME),
            _alert(alert_id="m2", source_ip="2.2.2.2", dest_ip=None, alert_type="phishing",
                   timestamp=BASE_TIME),
            _alert(alert_id="m3", source_ip="3.3.3.3", dest_ip=None, alert_type="phishing",
                   timestamp=BASE_TIME),
        ]
        incidents = correlate(alerts)

        assert len(incidents) == 3
        assert all(i["correlation_rule"] == "singleton" for i in incidents)


# ---------------------------------------------------------------------------
# FP exclusion
# ---------------------------------------------------------------------------

class TestFPExclusion:

    def test_fp_alerts_excluded(self):
        """Alerts marked is_false_positive=True should produce 0 incidents."""
        alerts = [
            _alert(alert_id="fp1", is_false_positive=True),
            _alert(alert_id="fp2", is_false_positive=True),
        ]
        incidents = correlate(alerts)
        assert incidents == []

    def test_mixed_fp_and_genuine(self):
        """FP alerts are excluded; genuine alerts are still correlated normally."""
        alerts = [
            _alert(alert_id="g1", source_ip="20.20.20.20", is_false_positive=False,
                   alert_type="brute_force", timestamp=BASE_TIME),
            _alert(alert_id="fp1", source_ip="20.20.20.20", is_false_positive=True,
                   alert_type="recon", timestamp=BASE_TIME + timedelta(minutes=5)),
        ]
        incidents = correlate(alerts)

        # Only the genuine alert remains; FP is excluded
        all_alert_ids = [aid for i in incidents for aid in i["alert_ids"]]
        assert "g1" in all_alert_ids
        assert "fp1" not in all_alert_ids

    def test_all_genuine_alerts_assigned(self):
        """Every genuine alert should appear in exactly one incident (no alert left out,
        no alert duplicated across incidents)."""
        # Use dest_ip=None so the dest_cluster rule cannot group these alerts
        alerts = [
            _alert(alert_id="ag1", source_ip="30.30.30.1", dest_ip=None,
                   timestamp=BASE_TIME),
            _alert(alert_id="ag2", source_ip="30.30.30.2", dest_ip=None,
                   timestamp=BASE_TIME),
            _alert(alert_id="ag3", source_ip="30.30.30.3", dest_ip=None,
                   timestamp=BASE_TIME),
        ]
        incidents = correlate(alerts)

        all_alert_ids = [aid for i in incidents for aid in i["alert_ids"]]
        assert set(all_alert_ids) == {"ag1", "ag2", "ag3"}
        # No duplicates
        assert len(all_alert_ids) == len(set(all_alert_ids))
