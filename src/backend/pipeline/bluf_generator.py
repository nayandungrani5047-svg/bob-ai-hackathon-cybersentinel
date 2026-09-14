"""
D2 Threat Intelligence — BLUF Generator
=========================================

Generates a Bottom Line Up Front (BLUF) narrative for a correlated, prioritised
incident.

Two modes
---------
Template mode (default / always-available fallback):
    Builds a structured BLUF string from incident fields, techniques, and alerts.
    No external dependencies.

watsonx.ai stub (optional):
    Enabled via the ``WATSONX_ENABLED=true`` environment variable.
    Attempts a real call to the watsonx.ai text-generation endpoint.
    Falls back to template mode on ANY exception or missing credential.

    # WATSONX STUB: Replace with real credentials and endpoint to enable
    # AI-generated BLUF.  Set the following environment variables:
    #   WATSONX_API_KEY      — IBM Cloud API key
    #   WATSONX_PROJECT_ID   — watsonx.ai project ID
    #   WATSONX_MODEL_ID     — model to use (default: ibm/granite-13b-chat-v2)
    #   WATSONX_URL          — regional API base URL
    #                          e.g. https://us-south.ml.cloud.ibm.com

Pure function path — no DB access, no SQLAlchemy, no FastAPI imports.
The watsonx stub does make an HTTP call when explicitly enabled; the template
path is completely side-effect free.
"""

import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action map keyed by severity label
# ---------------------------------------------------------------------------
_ACTION_MAP: dict[str, str] = {
    "Critical": (
        "IMMEDIATE: Isolate affected systems, escalate to incident response team, "
        "initiate containment procedures."
    ),
    "High": (
        "URGENT: Escalate to senior analyst within 1 hour. "
        "Investigate affected systems and block source IPs."
    ),
    "Medium": (
        "INVESTIGATE: Review within 4 hours. "
        "Correlate with additional telemetry sources."
    ),
    "Low": "MONITOR: Log for trend analysis. No immediate action required.",
}

_DEFAULT_ACTION = "REVIEW: Assess alert context and determine appropriate response."


# ---------------------------------------------------------------------------
# Template-mode helpers
# ---------------------------------------------------------------------------

def _format_source_list(sources: list[str]) -> str:
    if not sources:
        return "unknown source(s)"
    if len(sources) == 1:
        return sources[0]
    return ", ".join(sources[:-1]) + f" and {sources[-1]}"


def _format_ip_list(ips: list[str]) -> str:
    if not ips:
        return "unknown IP(s)"
    if len(ips) == 1:
        return ips[0]
    if len(ips) <= 3:
        return ", ".join(ips)
    return ", ".join(ips[:3]) + f" (+{len(ips) - 3} more)"


def _chain_description(incident: dict) -> str:
    """Derive a campaign/chain label from the incident."""
    rule = incident.get("correlation_rule", "singleton")
    alert_types = incident.get("alert_types", [])

    if rule == "attack_chain":
        stages = [t.replace("_", " ") for t in alert_types]
        return " → ".join(stages) + " attack chain"
    if rule == "same_ip_window":
        return "repeated activity campaign"
    if rule == "dest_cluster":
        return "coordinated targeting campaign"
    # singleton or unknown
    return (alert_types[0].replace("_", " ") if alert_types else "security") + " event"


def _evidence_summary(alerts: list[dict]) -> str:
    """Short evidence paragraph for the KEY EVIDENCE section."""
    if not alerts:
        return "No correlated alert evidence available."

    parts: list[str] = []

    # Highest-severity alert
    sev_order = ["critical", "high", "medium", "low", "informational"]
    sorted_alerts = sorted(
        alerts,
        key=lambda a: sev_order.index(a.get("severity_raw", "low").lower())
        if a.get("severity_raw", "low").lower() in sev_order
        else 99,
    )
    top = sorted_alerts[0]
    parts.append(
        f"Highest-severity alert: {top.get('severity_raw', 'unknown').upper()} "
        f"{top.get('alert_type', '')} from {top.get('source_ip', 'unknown')} "
        f"(confidence: {top.get('confidence', 0):.2f})."
    )

    # Alert count
    parts.append(f"Total correlated alerts: {len(alerts)}.")

    # Time span
    timestamps = [a["timestamp"] for a in alerts if a.get("timestamp")]
    if len(timestamps) >= 2:
        earliest = min(timestamps)
        latest = max(timestamps)
        span_mins = (latest - earliest).total_seconds() / 60
        parts.append(f"Activity window: {span_mins:.0f} minutes.")

    return " ".join(parts)


def _build_template_bluf(
    incident: dict,
    techniques: list[dict],
    alerts: list[dict],
) -> str:
    """Construct the full structured BLUF string from incident data."""
    count = len(alerts)
    sources = incident.get("sources", [])
    severity = incident.get("severity", "Unknown")
    source_ips = incident.get("source_ips", [])
    alert_types = incident.get("alert_types", [])
    dest_ips = list(
        dict.fromkeys(a.get("dest_ip") for a in alerts if a.get("dest_ip"))
    )

    chain_desc = _chain_description(incident)
    technique_names = (
        ", ".join(f"{t['id']} {t['name']}" for t in techniques)
        if techniques
        else "None identified"
    )
    action = _ACTION_MAP.get(severity, _DEFAULT_ACTION)

    # Destination description
    if dest_ips:
        dest_description = _format_ip_list(dest_ips)
    else:
        dest_description = "internal infrastructure"

    # Alert types in readable form
    alert_types_description = (
        " / ".join(t.replace("_", " ") for t in alert_types)
        if alert_types
        else "mixed"
    )

    evidence = _evidence_summary(alerts)

    bluf = (
        f"[BLUF] {count} correlated alert(s) from {_format_source_list(sources)} "
        f"indicate a {severity} {chain_desc} campaign.\n\n"
        f"WHAT HAPPENED: {alert_types_description} activity detected originating from "
        f"{_format_ip_list(source_ips)} targeting {dest_description}.\n\n"
        f"KEY EVIDENCE: {evidence}\n\n"
        f"MITRE ATT&CK: {technique_names}\n\n"
        f"RECOMMENDED ACTION: {action}"
    )
    return bluf


# ---------------------------------------------------------------------------
# watsonx.ai stub
# ---------------------------------------------------------------------------

def _call_watsonx(incident: dict, techniques: list[dict], alerts: list[dict]) -> str:
    """Attempt to generate a BLUF via watsonx.ai text generation.

    # WATSONX STUB: Replace with real credentials and endpoint to enable
    # AI-generated BLUF.  Set environment variables:
    #   WATSONX_API_KEY, WATSONX_PROJECT_ID, WATSONX_MODEL_ID, WATSONX_URL
    # This function will raise on any error so the caller can fall back.
    """
    import requests  # local import — only used in the stub path

    api_key = os.environ.get("WATSONX_API_KEY", "")
    project_id = os.environ.get("WATSONX_PROJECT_ID", "")
    model_id = os.environ.get("WATSONX_MODEL_ID", "ibm/granite-13b-chat-v2")
    watsonx_url = os.environ.get(
        "WATSONX_URL", "https://us-south.ml.cloud.ibm.com"
    )

    if not api_key or not project_id:
        raise ValueError("WATSONX_API_KEY and WATSONX_PROJECT_ID must be set.")

    # --- IAM token exchange ---
    iam_resp = requests.post(
        "https://iam.cloud.ibm.com/identity/token",
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": api_key,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    iam_resp.raise_for_status()
    access_token = iam_resp.json()["access_token"]

    # --- Build prompt ---
    technique_names = ", ".join(f"{t['id']} {t['name']}" for t in techniques)
    prompt = (
        f"You are a cybersecurity analyst. Write a concise 3-sentence BLUF "
        f"(Bottom Line Up Front) for the following security incident.\n\n"
        f"Incident title: {incident.get('title', 'Unknown')}\n"
        f"Severity: {incident.get('severity', 'Unknown')}\n"
        f"Priority score: {incident.get('priority_score', 0):.0f}/100\n"
        f"Alert count: {len(alerts)}\n"
        f"Source IPs: {', '.join(incident.get('source_ips', []))}\n"
        f"Alert types: {', '.join(incident.get('alert_types', []))}\n"
        f"MITRE techniques: {technique_names}\n"
        f"Priority reasoning: {incident.get('priority_reasoning', '')}\n\n"
        f"BLUF:"
    )

    # --- POST to watsonx.ai text generation endpoint ---
    gen_resp = requests.post(
        f"{watsonx_url}/ml/v1/text/generation?version=2024-05-01",
        json={
            "model_id": model_id,
            "project_id": project_id,
            "input": prompt,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": 300,
                "stop_sequences": ["\n\n"],
            },
        },
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        timeout=30,
    )
    gen_resp.raise_for_status()
    generated = gen_resp.json()["results"][0]["generated_text"].strip()
    return f"[BLUF — AI Generated]\n\n{generated}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_bluf(
    incident: dict,
    techniques: list[dict],
    alerts: list[dict],
) -> str:
    """Generate a BLUF narrative for one incident.

    Parameters
    ----------
    incident:
        Prioritised incident dict (output of ``prioritise()``).
    techniques:
        List of MITRE technique dicts (output of ``map_techniques()``).
    alerts:
        The alert dicts correlated into this incident.

    Returns
    -------
    str
        Structured BLUF string.  If ``WATSONX_ENABLED=true`` and credentials
        are present the text is AI-generated; otherwise the template is used.
        On any watsonx error the function silently falls back to template mode.
    """
    watsonx_enabled = os.environ.get("WATSONX_ENABLED", "false").lower() == "true"

    if watsonx_enabled:
        try:
            logger.info("watsonx.ai BLUF generation enabled — attempting API call.")
            return _call_watsonx(incident, techniques, alerts)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "watsonx.ai BLUF generation failed (%s) — falling back to template.",
                exc,
            )

    return _build_template_bluf(incident, techniques, alerts)
