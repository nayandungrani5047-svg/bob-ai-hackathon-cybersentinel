"""
D2 Threat Intelligence — False-Positive Classifier
====================================================

Applies four heuristic rules (first match wins) to each normalised alert dict
and marks it as a false positive when a rule fires.

Pure function — no DB access, no HTTP calls, no side effects.
"""

import copy
import logging
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule definitions
# Each rule is a tuple of (predicate_fn, fp_reason_string).
# Predicates receive the alert dict and the safe_ips set.
# Rules are evaluated in order; the first match wins.
# ---------------------------------------------------------------------------

def _rule_safe_ip(alert: dict, safe_ips: set[str]) -> bool:
    """Rule 1 — source IP is on the trusted/known-safe list."""
    return alert.get("source_ip", "") in safe_ips


def _rule_low_confidence(alert: dict, safe_ips: set[str]) -> bool:
    """Rule 2 — confidence score is below the actionable threshold."""
    return float(alert.get("confidence", 0.5)) < 0.3


def _rule_informational(alert: dict, safe_ips: set[str]) -> bool:
    """Rule 3 — severity is informational; below action threshold."""
    return str(alert.get("severity_raw", "")).lower() == "informational"


def _rule_low_confidence_scan(alert: dict, safe_ips: set[str]) -> bool:
    """Rule 4 — isolated low-confidence network scan."""
    return (
        str(alert.get("alert_type", "")).lower() == "scan"
        and float(alert.get("confidence", 0.5)) < 0.5
    )


_RULES: list[tuple] = [
    (_rule_safe_ip,            "Known-safe/trusted IP address"),
    (_rule_low_confidence,     "Insufficient source confidence (< 0.30)"),
    (_rule_informational,      "Informational-only alert, below action threshold"),
    (_rule_low_confidence_scan,"Isolated low-confidence network scan"),
]


def classify_fps(alerts: list[dict], safe_ips: list[str]) -> list[dict]:
    """Apply FP heuristics to each alert.

    Parameters
    ----------
    alerts:
        List of normalised alert dicts (output of ``normalise()``).
    safe_ips:
        List of known-safe/trusted IP address strings (from safe_ips.json).

    Returns
    -------
    list[dict]
        New list of alert dicts.  Alerts that match a rule have
        ``is_false_positive=True`` and ``fp_reason`` set to a human-readable
        explanation.  Non-matching alerts are returned unchanged.  The
        original dicts are never mutated.
    """
    safe_ip_set = set(safe_ips)
    result: list[dict] = []

    for alert in alerts:
        classified = copy.copy(alert)  # shallow copy — sufficient for flat dicts

        for predicate, reason in _RULES:
            if predicate(classified, safe_ip_set):
                classified["is_false_positive"] = True
                classified["fp_reason"] = reason
                logger.debug(
                    "Alert %s marked FP: %s", classified.get("id"), reason
                )
                break  # first match wins

        result.append(classified)

    fp_count = sum(1 for a in result if a.get("is_false_positive"))
    logger.info("FP classification complete: %d/%d alerts flagged.", fp_count, len(result))
    return result
