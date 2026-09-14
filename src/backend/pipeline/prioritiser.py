"""
D2 Threat Intelligence — Prioritiser
======================================

Computes a priority score (0–100) for a single incident and assigns a
human-readable severity label and reasoning string.

Scoring algorithm
-----------------
1. Base severity score (highest-severity alert in the incident):
   critical=40, high=30, medium=15, low=5, informational=0

2. Alert-count score (capped at 5 alerts):
   1→5, 2→10, 3→15, 4→20, 5+→25

3. Multi-stage chain bonus:
   correlation_rule == "attack_chain" → +20

4. Confidence factor:
   avg_confidence × score  (floor of 0.3 so high-severity incidents
   are never zeroed out by a low-confidence average)

5. Recurrence bonus:
   More than 3 alerts from the same source_ip in the incident → +5

Final score is clamped to 0–100.

Severity thresholds
-------------------
75–100 → Critical
55–74  → High
30–54  → Medium
0–29   → Low

Pure function — no DB access, no HTTP calls, no side effects.
"""

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

_SEVERITY_BASE: dict[str, int] = {
    "critical": 40,
    "high": 30,
    "medium": 15,
    "low": 5,
    "informational": 0,
}

_COUNT_SCORE: dict[int, int] = {1: 5, 2: 10, 3: 15, 4: 20}
_COUNT_SCORE_MAX = 25  # 5 or more alerts

_SEVERITY_THRESHOLDS: list[tuple[int, str]] = [
    (75, "Critical"),
    (55, "High"),
    (30, "Medium"),
    (0,  "Low"),
]


def _score_to_severity(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def _highest_severity(severity_list: list[str]) -> str:
    """Return the most severe label from the list."""
    order = ["critical", "high", "medium", "low", "informational"]
    for level in order:
        if level in [s.lower() for s in severity_list]:
            return level
    return "low"


def prioritise(incident: dict, alerts: list[dict]) -> dict:
    """Compute priority score and severity for one incident.

    Parameters
    ----------
    incident:
        Incident dict produced by ``correlate()``.
    alerts:
        The full list of alert dicts (all alerts, not just the incident's).
        The function selects the relevant alerts using ``incident["alert_ids"]``.

    Returns
    -------
    dict
        Copy of the incident dict with three new keys:
        ``severity``, ``priority_score``, ``priority_reasoning``.
    """
    alert_id_set = set(incident.get("alert_ids", []))
    incident_alerts = [a for a in alerts if a["id"] in alert_id_set]

    # ------------------------------------------------------------------
    # 1. Base severity score
    # ------------------------------------------------------------------
    severities = [a.get("severity_raw", "low").lower() for a in incident_alerts]
    top_severity = _highest_severity(severities)
    base_score = _SEVERITY_BASE.get(top_severity, 5)

    # ------------------------------------------------------------------
    # 2. Alert count score
    # ------------------------------------------------------------------
    alert_count = len(incident_alerts)
    count_score = _COUNT_SCORE.get(alert_count, _COUNT_SCORE_MAX)

    # ------------------------------------------------------------------
    # 3. Multi-stage chain bonus
    # ------------------------------------------------------------------
    chain_bonus = 20 if incident.get("correlation_rule") == "attack_chain" else 0

    # ------------------------------------------------------------------
    # 4. Confidence factor (floor 0.3)
    # ------------------------------------------------------------------
    confidences = [float(a.get("confidence", 0.5)) for a in incident_alerts]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
    confidence_factor = max(avg_confidence, 0.3)

    # Raw score before confidence scaling
    raw_score = base_score + count_score + chain_bonus

    # Apply confidence factor
    scaled_score = raw_score * confidence_factor

    # ------------------------------------------------------------------
    # 5. Recurrence bonus
    # ------------------------------------------------------------------
    source_ip_counts: dict[str, int] = {}
    for a in incident_alerts:
        ip = a.get("source_ip", "")
        source_ip_counts[ip] = source_ip_counts.get(ip, 0) + 1

    recurrence_bonus = 5 if any(c > 3 for c in source_ip_counts.values()) else 0

    # Final score — add recurrence bonus AFTER confidence scaling, clamp
    final_score = min(100.0, max(0.0, scaled_score + recurrence_bonus))
    severity_label = _score_to_severity(final_score)

    # ------------------------------------------------------------------
    # Build human-readable reasoning string
    # ------------------------------------------------------------------
    # Pick the single most notable alert for the reasoning line
    notable_alert = next(
        (a for a in incident_alerts if a.get("severity_raw", "").lower() == top_severity),
        incident_alerts[0] if incident_alerts else None,
    )
    notable_desc = (
        f"{top_severity} {notable_alert['alert_type']} from {notable_alert['source_ip']}"
        if notable_alert
        else "n/a"
    )

    reasoning_parts = [
        f"Score: {final_score:.0f}/100.",
        f"Base severity: {top_severity.title()} ({base_score}pts).",
        f"Alert count: {alert_count} correlated alert(s) ({count_score}pts).",
    ]
    if chain_bonus:
        reasoning_parts.append("Multi-stage attack chain bonus (20pts).")
    reasoning_parts.append(f"Confidence factor: {avg_confidence:.2f}.")
    if recurrence_bonus:
        reasoning_parts.append("Recurrence bonus: >3 alerts from same source IP (+5pts).")
    reasoning_parts.append(f"Highest-severity alert: {notable_desc}.")

    priority_reasoning = " ".join(reasoning_parts)

    logger.debug(
        "Incident %s → severity=%s score=%.1f",
        incident.get("id"),
        severity_label,
        final_score,
    )

    return {
        **incident,
        "severity": severity_label,
        "priority_score": round(final_score, 2),
        "priority_reasoning": priority_reasoning,
    }
