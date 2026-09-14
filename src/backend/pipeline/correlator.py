"""
D2 Threat Intelligence — Correlator
=====================================

Groups non-FP alerts into incidents using four rules applied in sequence.

Rules
-----
1. **Attack-chain pattern** — same source_ip with ≥3 of the known chain
   stage alert_types within a 6-hour window → "multi-stage incident".
2. **Same-IP time window** — same source_ip within a 30-minute sliding
   window (minimum 2 alerts) → "repeated activity" incident.
3. **Same-destination cluster** — same dest_ip targeted within 1 hour,
   different source_ips, minimum 2 alerts → "targeted attack" incident.
4. **Singleton** — any alert not yet assigned → its own incident.

FP alerts are never correlated; they retain ``incident_id=None``.

Pure function — no DB access, no HTTP calls, no side effects.
"""

import copy
import logging
import uuid
from datetime import datetime, timedelta
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Stage types that constitute an "attack chain" (order matters for description)
CHAIN_STAGES = [
    "recon",
    "brute_force",
    "lateral_movement",
    "privilege_escalation",
    "malware",
    "data_exfil",
]
CHAIN_WINDOW = timedelta(hours=6)
SAME_IP_WINDOW = timedelta(minutes=30)
DEST_CLUSTER_WINDOW = timedelta(hours=1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_incident(
    title: str,
    rule: str,
    alerts: list[dict],
) -> dict:
    """Build a fresh incident dict from a group of correlated alerts."""
    alert_ids = [a["id"] for a in alerts]
    alert_types = list(dict.fromkeys(a["alert_type"] for a in alerts))  # preserves order, deduped
    source_ips = list(dict.fromkeys(a["source_ip"] for a in alerts))
    severities = [a["severity_raw"] for a in alerts]
    confidences = [float(a.get("confidence", 0.5)) for a in alerts]
    timestamps = [a["timestamp"] for a in alerts]
    sources = list(dict.fromkeys(a["raw_source"] for a in alerts))

    return {
        "id": str(uuid.uuid4()),
        "title": title,
        "alert_ids": alert_ids,
        "alert_types": alert_types,
        "source_ips": source_ips,
        "severity_raw_list": severities,
        "confidences": confidences,
        "timestamps": timestamps,
        "correlation_rule": rule,
        "sources": sources,
    }


def _alerts_within_window(alerts: list[dict], window: timedelta) -> bool:
    """Return True if the span from earliest to latest timestamp ≤ window."""
    if len(alerts) < 2:
        return True
    times = sorted(a["timestamp"] for a in alerts)
    return (times[-1] - times[0]) <= window


def _chain_description(types_present: list[str]) -> str:
    """Build a readable chain description from the matching stage types."""
    ordered = [s for s in CHAIN_STAGES if s in types_present]
    return " → ".join(t.replace("_", " ") for t in ordered)


# ---------------------------------------------------------------------------
# Core correlation function
# ---------------------------------------------------------------------------

def correlate(alerts: list[dict]) -> list[dict]:
    """Group non-FP alerts into incident dicts.

    Parameters
    ----------
    alerts:
        List of normalised + FP-classified alert dicts.

    Returns
    -------
    list[dict]
        Incident dicts.  The input alert dicts are not mutated here; the
        caller (ingest pipeline) is responsible for updating ``incident_id``
        on each alert using the returned incident data.
    """
    # Separate genuine from FP — FP alerts are never correlated.
    genuine = [a for a in alerts if not a.get("is_false_positive")]
    unassigned_ids: set[str] = {a["id"] for a in genuine}

    incidents: list[dict] = []

    # -------------------------------------------------------------------
    # Rule 1 — Attack-chain pattern (highest priority)
    # Group by source_ip; look for ≥3 chain stage types within 6 h.
    # -------------------------------------------------------------------
    by_source: dict[str, list[dict]] = {}
    for alert in genuine:
        by_source.setdefault(alert["source_ip"], []).append(alert)

    for src_ip, src_alerts in by_source.items():
        # Only consider alerts still unassigned
        candidates = [a for a in src_alerts if a["id"] in unassigned_ids]
        if len(candidates) < 2:
            continue

        types_present = {a["alert_type"] for a in candidates}
        chain_matches = [s for s in CHAIN_STAGES if s in types_present]

        if len(chain_matches) < 3:
            continue

        # Check that the chain stages all fall within the 6-hour window.
        # Use only the alerts whose type participates in the chain.
        chain_alerts = [a for a in candidates if a["alert_type"] in chain_matches]
        if not _alerts_within_window(chain_alerts, CHAIN_WINDOW):
            continue

        chain_desc = _chain_description(list(types_present))
        title = f"Multi-Stage Attack: {chain_desc} from {src_ip}"
        incident = _new_incident(title, "attack_chain", candidates)
        incidents.append(incident)
        # Mark all candidates (not only chain_alerts) as assigned so the
        # same-IP rule doesn't re-group the remaining same-IP alerts.
        for a in candidates:
            unassigned_ids.discard(a["id"])

    # -------------------------------------------------------------------
    # Rule 2 — Same-IP, 30-minute sliding window (minimum 2 alerts)
    # -------------------------------------------------------------------
    # Rebuild by-source with only unassigned alerts
    remaining_genuine = [a for a in genuine if a["id"] in unassigned_ids]
    by_source2: dict[str, list[dict]] = {}
    for alert in remaining_genuine:
        by_source2.setdefault(alert["source_ip"], []).append(alert)

    for src_ip, src_alerts in by_source2.items():
        if len(src_alerts) < 2:
            continue

        # Sort by timestamp and apply a sliding window
        sorted_alerts = sorted(src_alerts, key=lambda a: a["timestamp"])
        grouped: list[list[dict]] = []
        current_window: list[dict] = [sorted_alerts[0]]

        for alert in sorted_alerts[1:]:
            window_start = current_window[0]["timestamp"]
            if (alert["timestamp"] - window_start) <= SAME_IP_WINDOW:
                current_window.append(alert)
            else:
                if len(current_window) >= 2:
                    grouped.append(current_window)
                current_window = [alert]

        if len(current_window) >= 2:
            grouped.append(current_window)

        for group in grouped:
            # Representative alert type is the most common in this group
            type_counts: dict[str, int] = {}
            for a in group:
                type_counts[a["alert_type"]] = type_counts.get(a["alert_type"], 0) + 1
            rep_type = max(type_counts, key=lambda t: type_counts[t])

            title = f"Repeated Activity: {rep_type} from {src_ip}"
            incident = _new_incident(title, "same_ip_window", group)
            incidents.append(incident)
            for a in group:
                unassigned_ids.discard(a["id"])

    # -------------------------------------------------------------------
    # Rule 3 — Same-destination cluster (min 2 alerts, different source_ips,
    # within 1-hour window)
    # -------------------------------------------------------------------
    remaining_genuine2 = [a for a in genuine if a["id"] in unassigned_ids]
    by_dest: dict[str, list[dict]] = {}
    for alert in remaining_genuine2:
        dest = alert.get("dest_ip")
        if dest:
            by_dest.setdefault(dest, []).append(alert)

    for dest_ip, dest_alerts in by_dest.items():
        if len(dest_alerts) < 2:
            continue

        # Need at least 2 different source IPs
        src_ips_in_group = {a["source_ip"] for a in dest_alerts}
        if len(src_ips_in_group) < 2:
            continue

        if not _alerts_within_window(dest_alerts, DEST_CLUSTER_WINDOW):
            # Try to find a sub-window that qualifies
            sorted_dest = sorted(dest_alerts, key=lambda a: a["timestamp"])
            sub: list[dict] = []
            for alert in sorted_dest:
                sub.append(alert)
                if (sub[-1]["timestamp"] - sub[0]["timestamp"]) > DEST_CLUSTER_WINDOW:
                    sub.pop(0)
                if len(sub) >= 2 and len({a["source_ip"] for a in sub}) >= 2:
                    dest_alerts = list(sub)
                    break
            else:
                continue

        title = f"Targeted Attack on {dest_ip}"
        incident = _new_incident(title, "dest_cluster", dest_alerts)
        incidents.append(incident)
        for a in dest_alerts:
            unassigned_ids.discard(a["id"])

    # -------------------------------------------------------------------
    # Rule 4 — Singleton: each remaining unassigned genuine alert
    # -------------------------------------------------------------------
    for alert in genuine:
        if alert["id"] not in unassigned_ids:
            continue
        alert_type_label = alert["alert_type"].replace("_", " ").title()
        src_ip = alert["source_ip"]
        title = f"{alert_type_label} Alert from {src_ip}"
        incident = _new_incident(title, "singleton", [alert])
        incidents.append(incident)
        unassigned_ids.discard(alert["id"])

    logger.info(
        "Correlation complete: %d incidents from %d genuine alerts.",
        len(incidents),
        len(genuine),
    )
    return incidents
