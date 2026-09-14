"""
Unit tests for pipeline/prioritiser.py
"""

import uuid
from datetime import datetime

import pytest

from pipeline.prioritiser import prioritise


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert(
    alert_id: str = None,
    source_ip: str = "192.168.1.100",
    alert_type: str = "brute_force",
    severity_raw: str = "high",
    confidence: float = 0.8,
):
    return {
        "id": alert_id or str(uuid.uuid4()),
        "raw_source": "SIEM-Alpha",
        "source_format": "siem",
        "source_ip": source_ip,
        "dest_ip": "10.0.0.5",
        "alert_type": alert_type,
        "description": "Test alert",
        "severity_raw": severity_raw,
        "confidence": confidence,
        "timestamp": datetime(2026, 1, 15, 8, 0, 0),
        "is_false_positive": False,
        "fp_reason": None,
        "incident_id": None,
    }


def _incident(alert_ids: list, rule: str = "singleton"):
    return {
        "id": str(uuid.uuid4()),
        "title": "Test Incident",
        "alert_ids": alert_ids,
        "alert_types": ["brute_force"],
        "source_ips": ["192.168.1.100"],
        "severity_raw_list": [],
        "confidences": [],
        "timestamps": [],
        "correlation_rule": rule,
        "sources": ["SIEM-Alpha"],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPrioritise:

    def test_critical_incident_scores_high(self):
        """Attack-chain incident with critical-severity alerts and high confidence
        should score in the High or Critical band (>= 55).

        Scoring math: base=40 (critical) + count=25 (5 alerts) + chain=20 → raw=85
        × confidence=0.95 → scaled=80.75 → Critical.
        With 3 alerts: base=40 + count=15 + chain=20 → raw=75 × 0.95 → 71.25 → High.
        We use 5 high-confidence alerts to reliably reach Critical (>= 75).
        """
        alerts = [
            _alert(alert_id=f"c{i}", alert_type="recon" if i == 0 else "brute_force",
                   severity_raw="critical", confidence=0.95)
            for i in range(5)
        ]
        incident = _incident([a["id"] for a in alerts], rule="attack_chain")

        result = prioritise(incident, alerts)

        assert result["severity"] in ("Critical", "High"), (
            f"Expected Critical or High, got {result['severity']} (score={result['priority_score']})"
        )
        assert result["priority_score"] >= 55

    def test_medium_incident(self):
        """Singleton with medium-severity and moderate confidence should score in Medium/Low range."""
        alerts = [
            _alert(alert_id="m1", alert_type="scan", severity_raw="medium", confidence=0.6),
        ]
        incident = _incident(["m1"], rule="singleton")

        result = prioritise(incident, alerts)

        assert result["severity"] in ("Medium", "Low"), (
            f"Expected Medium or Low, got {result['severity']} (score={result['priority_score']})"
        )

    def test_priority_reasoning_populated(self):
        """priority_reasoning must be a non-empty string."""
        alerts = [_alert(alert_id="r1")]
        incident = _incident(["r1"])
        result = prioritise(incident, alerts)

        assert isinstance(result["priority_reasoning"], str)
        assert len(result["priority_reasoning"]) > 0

    def test_score_clamped_to_100(self):
        """Even with maximum bonuses, priority_score must not exceed 100."""
        # Critical severity + 5 alerts (max count) + attack_chain rule + high confidence
        alerts = [
            _alert(alert_id=f"max{i}", severity_raw="critical", confidence=1.0)
            for i in range(5)
        ]
        incident = _incident([a["id"] for a in alerts], rule="attack_chain")
        result = prioritise(incident, alerts)

        assert result["priority_score"] <= 100.0

    def test_low_confidence_reduces_score(self):
        """Same incident with low confidence should score lower than with high confidence."""
        def _make_incident_and_alerts(confidence):
            alerts = [
                _alert(alert_id=f"ci{i}", severity_raw="high", confidence=confidence)
                for i in range(3)
            ]
            incident = _incident([a["id"] for a in alerts], rule="same_ip_window")
            return incident, alerts

        low_incident, low_alerts   = _make_incident_and_alerts(0.2)
        high_incident, high_alerts = _make_incident_and_alerts(0.9)

        low_result  = prioritise(low_incident, low_alerts)
        high_result = prioritise(high_incident, high_alerts)

        assert low_result["priority_score"] < high_result["priority_score"], (
            f"Low confidence score ({low_result['priority_score']}) should be less than "
            f"high confidence score ({high_result['priority_score']})"
        )

    def test_chain_bonus_applied(self):
        """attack_chain rule should produce a higher score than singleton for identical alerts."""
        alerts = [
            _alert(alert_id=f"b{i}", severity_raw="high", confidence=0.8)
            for i in range(3)
        ]
        ids = [a["id"] for a in alerts]

        chain_result     = prioritise(_incident(ids, rule="attack_chain"), alerts)
        singleton_result = prioritise(_incident(ids[:1], rule="singleton"), alerts[:1])

        assert chain_result["priority_score"] > singleton_result["priority_score"]

    def test_severity_thresholds(self):
        """Score→severity mapping: >= 75 = Critical, 55-74 = High, 30-54 = Medium, < 30 = Low."""
        # A single low-severity, low-confidence alert → Low or Medium
        low_alerts = [_alert(alert_id="l1", severity_raw="low", confidence=0.4)]
        low_result = prioritise(_incident(["l1"], rule="singleton"), low_alerts)
        assert low_result["severity"] in ("Low", "Medium")

        # A single high-severity, high-confidence, attack_chain alert → High or Critical
        high_alerts = [
            _alert(alert_id=f"h{i}", severity_raw="high", confidence=0.95)
            for i in range(5)
        ]
        ids = [a["id"] for a in high_alerts]
        high_result = prioritise(_incident(ids, rule="attack_chain"), high_alerts)
        assert high_result["severity"] in ("High", "Critical")

    def test_result_contains_original_incident_fields(self):
        """prioritise() must return a copy that still contains all original incident keys."""
        alerts = [_alert(alert_id="orig1")]
        incident = _incident(["orig1"])
        result = prioritise(incident, alerts)

        for key in ("id", "title", "alert_ids", "correlation_rule"):
            assert key in result, f"Original key '{key}' missing from result"

    def test_empty_alerts_handled_gracefully(self):
        """An incident whose alert_ids reference no alerts should not raise."""
        incident = _incident(["nonexistent-id"])
        result = prioritise(incident, [])  # empty alerts list

        assert "priority_score" in result
        assert "severity" in result
        assert "priority_reasoning" in result
