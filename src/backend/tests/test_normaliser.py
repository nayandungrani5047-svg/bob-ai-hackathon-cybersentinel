"""
Unit tests for pipeline/normaliser.py
"""

from datetime import datetime

import pytest

from pipeline.normaliser import normalise


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_siem_alert(**overrides):
    base = {
        "id": "alert-siem-001",
        "source": "SIEM-Alpha",
        "format": "siem",
        "timestamp": "2026-01-15T08:00:00Z",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "alert_type": "brute_force",
        "description": "Multiple failed login attempts.",
        "severity": "high",
        "confidence": 0.85,
        "extra": {"attempts": 50},
    }
    base.update(overrides)
    return base


def _make_sensor_alert(**overrides):
    base = {
        "id": "alert-sensor-001",
        "source": "EDR-Sensor-1",
        "format": "sensor",
        "timestamp": "2026-01-15T09:30:00Z",
        "source_ip": "10.1.2.3",
        "dest_ip": "172.16.0.1",
        "alert_type": "malware",
        "description": "Suspicious process execution detected.",
        "severity": "critical",
        "confidence": 0.92,
        "extra": {"process": "cmd.exe"},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNormalise:

    def test_normalises_siem_format(self):
        """SIEM-format alert is correctly mapped to all canonical fields."""
        raw = _make_siem_alert()
        result = normalise([raw])

        assert len(result) == 1
        n = result[0]

        # Identity / source metadata
        assert n["id"] == "alert-siem-001"
        assert n["raw_source"] == "SIEM-Alpha"
        assert n["source_format"] == "siem"

        # Network
        assert n["source_ip"] == "192.168.1.100"
        assert n["dest_ip"] == "10.0.0.5"

        # Classification
        assert n["alert_type"] == "brute_force"
        assert n["severity_raw"] == "high"
        assert n["confidence"] == pytest.approx(0.85)

        # FP defaults
        assert n["is_false_positive"] is False
        assert n["fp_reason"] is None
        assert n["incident_id"] is None

    def test_normalises_sensor_format(self):
        """Sensor-format alert is mapped correctly, including critical severity."""
        raw = _make_sensor_alert()
        result = normalise([raw])

        assert len(result) == 1
        n = result[0]

        assert n["source_format"] == "sensor"
        assert n["raw_source"] == "EDR-Sensor-1"
        assert n["alert_type"] == "malware"
        assert n["severity_raw"] == "critical"
        assert n["confidence"] == pytest.approx(0.92)

    def test_handles_missing_dest_ip(self):
        """Alert without dest_ip should have dest_ip=None in the output."""
        raw = _make_siem_alert()
        del raw["dest_ip"]
        result = normalise([raw])

        assert len(result) == 1
        assert result[0]["dest_ip"] is None

    def test_handles_missing_confidence(self):
        """Alert without a confidence field defaults to 0.5."""
        raw = _make_siem_alert()
        del raw["confidence"]
        result = normalise([raw])

        assert len(result) == 1
        assert result[0]["confidence"] == pytest.approx(0.5)

    def test_timestamp_parsed_to_datetime(self):
        """The timestamp field in the output should be a datetime object, not a string."""
        raw = _make_siem_alert(timestamp="2026-01-15T08:00:00Z")
        result = normalise([raw])

        assert len(result) == 1
        ts = result[0]["timestamp"]
        assert isinstance(ts, datetime), f"Expected datetime, got {type(ts)}"
        assert ts.year == 2026
        assert ts.month == 1
        assert ts.day == 15
        assert ts.hour == 8

    def test_skips_alert_missing_required_field(self):
        """Alert missing a required field (e.g. source_ip) is skipped with no error."""
        raw = _make_siem_alert()
        del raw["source_ip"]
        result = normalise([raw])
        assert result == []

    def test_skips_alert_missing_id(self):
        """Alert missing 'id' is skipped."""
        raw = _make_siem_alert()
        del raw["id"]
        result = normalise([raw])
        assert result == []

    def test_multiple_alerts_all_normalised(self):
        """All valid alerts in a list are normalised; invalid ones are skipped."""
        raw1 = _make_siem_alert(id="a1")
        raw2 = _make_sensor_alert(id="a2")
        bad = _make_siem_alert(id="a3")
        del bad["source_ip"]

        result = normalise([raw1, raw2, bad])
        assert len(result) == 2
        ids = {r["id"] for r in result}
        assert ids == {"a1", "a2"}

    def test_extra_data_serialised_to_json_string(self):
        """The 'extra' dict should be serialised to a JSON string in extra_data."""
        raw = _make_siem_alert(extra={"key": "value", "count": 3})
        result = normalise([raw])

        import json
        extra_data = result[0]["extra_data"]
        assert extra_data is not None
        parsed = json.loads(extra_data)
        assert parsed["key"] == "value"
        assert parsed["count"] == 3

    def test_extra_data_none_when_no_extra(self):
        """When no 'extra' field is present, extra_data should be None."""
        raw = _make_siem_alert()
        del raw["extra"]
        result = normalise([raw])
        assert result[0]["extra_data"] is None

    def test_description_defaults_to_empty_string(self):
        """Missing 'description' defaults to empty string, not None."""
        raw = _make_siem_alert()
        del raw["description"]
        result = normalise([raw])
        assert result[0]["description"] == ""
