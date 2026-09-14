"""
Unit tests for pipeline/fp_classifier.py
"""

import pytest

from pipeline.fp_classifier import classify_fps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert(**overrides):
    """Build a minimal normalised alert dict with sensible defaults."""
    base = {
        "id": "test-alert-001",
        "raw_source": "SIEM-Alpha",
        "source_format": "siem",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "alert_type": "brute_force",
        "description": "Test alert",
        "severity_raw": "high",
        "confidence": 0.8,
        "is_false_positive": False,
        "fp_reason": None,
        "incident_id": None,
    }
    base.update(overrides)
    return base


SAFE_IPS = ["10.0.0.50", "10.0.0.51", "45.33.32.156"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestClassifyFPs:

    def test_safe_ip_flagged(self):
        """Alert from a known-safe IP should be flagged as FP (Rule 1)."""
        alert = _alert(source_ip="10.0.0.50")
        result = classify_fps([alert], SAFE_IPS)

        assert len(result) == 1
        r = result[0]
        assert r["is_false_positive"] is True
        assert r["fp_reason"] is not None
        assert "trusted" in r["fp_reason"].lower() or "safe" in r["fp_reason"].lower()

    def test_low_confidence_flagged(self):
        """Alert with confidence < 0.30 should be flagged as FP (Rule 2)."""
        alert = _alert(confidence=0.2, source_ip="1.2.3.4")
        result = classify_fps([alert], SAFE_IPS)

        assert result[0]["is_false_positive"] is True
        assert "confidence" in result[0]["fp_reason"].lower()

    def test_informational_flagged(self):
        """Alert with severity_raw='informational' should be flagged as FP (Rule 3)."""
        alert = _alert(severity_raw="informational", source_ip="5.6.7.8", confidence=0.9)
        result = classify_fps([alert], SAFE_IPS)

        assert result[0]["is_false_positive"] is True
        assert "informational" in result[0]["fp_reason"].lower()

    def test_isolated_scan_flagged(self):
        """Low-confidence scan should be flagged as FP (Rule 4)."""
        alert = _alert(
            alert_type="scan",
            confidence=0.3,
            severity_raw="low",
            source_ip="9.9.9.9",
        )
        result = classify_fps([alert], SAFE_IPS)

        assert result[0]["is_false_positive"] is True

    def test_genuine_alert_not_flagged(self):
        """High-confidence brute_force from an unknown IP should NOT be flagged."""
        alert = _alert(
            source_ip="1.2.3.4",
            alert_type="brute_force",
            confidence=0.9,
            severity_raw="high",
        )
        result = classify_fps([alert], SAFE_IPS)

        assert result[0]["is_false_positive"] is False
        assert result[0]["fp_reason"] is None

    def test_does_not_mutate_input(self):
        """classify_fps must not mutate the original alert dicts."""
        alert = _alert(source_ip="10.0.0.50")
        original_fp = alert["is_false_positive"]
        original_reason = alert["fp_reason"]

        classify_fps([alert], SAFE_IPS)

        # Original dict should be unchanged
        assert alert["is_false_positive"] == original_fp
        assert alert["fp_reason"] == original_reason

    def test_first_rule_wins(self):
        """When both Rule 1 (safe IP) and Rule 2 (low confidence) would fire,
        Rule 1 fires first and its reason is used."""
        alert = _alert(source_ip="10.0.0.50", confidence=0.1)
        result = classify_fps([alert], SAFE_IPS)

        r = result[0]
        assert r["is_false_positive"] is True
        # Rule 1 fires first — reason should mention trusted/safe, not confidence
        assert "trusted" in r["fp_reason"].lower() or "safe" in r["fp_reason"].lower()

    def test_empty_safe_ips(self):
        """With an empty safe_ips list, only confidence/severity/scan rules apply."""
        alert = _alert(source_ip="10.0.0.50", confidence=0.9, severity_raw="high")
        result = classify_fps([alert], [])

        # Safe-IP list is empty, so this alert should not be flagged
        assert result[0]["is_false_positive"] is False

    def test_scan_with_high_confidence_not_flagged(self):
        """A scan alert with confidence >= 0.5 should NOT trigger Rule 4."""
        alert = _alert(
            alert_type="scan",
            confidence=0.7,
            severity_raw="medium",
            source_ip="2.2.2.2",
        )
        result = classify_fps([alert], SAFE_IPS)

        assert result[0]["is_false_positive"] is False

    def test_returns_all_alerts_including_genuine(self):
        """Output list length matches input list length."""
        alerts = [
            _alert(id="a1", source_ip="10.0.0.50"),   # FP (safe IP)
            _alert(id="a2", confidence=0.2),           # FP (low confidence)
            _alert(id="a3"),                            # genuine
        ]
        result = classify_fps(alerts, SAFE_IPS)

        assert len(result) == 3
        fp_ids = {r["id"] for r in result if r["is_false_positive"]}
        assert "a1" in fp_ids
        assert "a2" in fp_ids
        assert "a3" not in fp_ids
