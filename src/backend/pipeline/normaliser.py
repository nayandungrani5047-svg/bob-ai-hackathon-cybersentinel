"""
D2 Threat Intelligence — Normaliser
====================================

Maps raw alert dicts (from synthetic_alerts.json) to the canonical schema
that matches the Alert ORM model fields.

Pure function — no DB access, no HTTP calls, no side effects.
"""

import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Fields that must be present in the raw alert for it to be useful.
_REQUIRED_FIELDS = ("id", "source", "format", "timestamp", "source_ip", "alert_type", "severity")


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string to a UTC-aware datetime.

    Accepts strings with a trailing 'Z' (e.g. '2026-01-15T07:03:22Z') or a
    '+00:00' offset.  Falls back to datetime.utcnow() on any parse error.
    """
    if not ts_str:
        return datetime.utcnow()
    # Replace trailing Z with +00:00 for fromisoformat compatibility (Python < 3.11)
    normalised = ts_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalised)
        # Strip timezone info so SQLite (naive datetime column) stays consistent
        return dt.replace(tzinfo=None)
    except ValueError:
        logger.warning("Could not parse timestamp %r — using utcnow()", ts_str)
        return datetime.utcnow()


def normalise(raw_alerts: list[dict]) -> list[dict]:
    """Transform a list of raw alert dicts into normalised alert dicts.

    Parameters
    ----------
    raw_alerts:
        List of dicts loaded directly from synthetic_alerts.json.

    Returns
    -------
    list[dict]
        Each dict has keys matching the Alert ORM model columns.  Alerts that
        are missing critical required fields are skipped with a warning.
    """
    result: list[dict] = []

    for raw in raw_alerts:
        # Warn and skip alerts that are missing any required field.
        missing = [f for f in _REQUIRED_FIELDS if not raw.get(f)]
        if missing:
            logger.warning(
                "Alert %r is missing required fields %s — skipping.",
                raw.get("id", "<unknown>"),
                missing,
            )
            continue

        # Serialise the `extra` sub-dict to a JSON string (or None).
        extra_obj = raw.get("extra")
        extra_data: str | None = json.dumps(extra_obj) if extra_obj is not None else None

        normalised: dict = {
            # Identity
            "id": raw["id"],
            # Source metadata
            "raw_source": raw["source"],
            "source_format": raw["format"],
            # Timing
            "timestamp": _parse_timestamp(raw["timestamp"]),
            # Network
            "source_ip": raw["source_ip"],
            "dest_ip": raw.get("dest_ip"),  # nullable
            # Classification
            "alert_type": raw["alert_type"],
            "description": raw.get("description", ""),
            "severity_raw": raw["severity"],
            "confidence": float(raw.get("confidence", 0.5)),
            # FP fields — pipeline sets these; default to clean
            "is_false_positive": False,
            "fp_reason": None,
            # Incident linkage — set by correlator
            "incident_id": None,
            # Auxiliary
            "extra_data": extra_data,
            "created_at": datetime.utcnow(),
        }

        result.append(normalised)

    return result
