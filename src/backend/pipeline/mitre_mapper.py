"""
D2 Threat Intelligence — MITRE ATT&CK Mapper
==============================================

Maps a list of alert_type strings to deduplicated MITRE ATT&CK technique dicts
using the local mitre_mapping.json reference file.

Pure function — no DB access, no HTTP calls, no side effects.
"""

import logging

logger = logging.getLogger(__name__)


def map_techniques(alert_types: list[str], mitre_mapping: dict) -> list[dict]:
    """Return a deduplicated list of MITRE ATT&CK technique dicts.

    Parameters
    ----------
    alert_types:
        List of alert_type strings (e.g. ``["brute_force", "recon", "malware"]``).
        May contain duplicates — they will be collapsed.
    mitre_mapping:
        The dict loaded from ``mitre_mapping.json``.  Each key is an alert_type
        string; each value is a list of technique dicts with keys
        ``id``, ``name``, and ``tactic``.

    Returns
    -------
    list[dict]
        Deduplicated list of ``{"id": str, "name": str, "tactic": str}`` dicts.
        Deduplication is by technique ID — if the same technique ID appears via
        multiple alert_types it is included only once.
    """
    seen_ids: set[str] = set()
    techniques: list[dict] = []

    for alert_type in alert_types:
        # Look up this alert_type in the mapping (case-insensitive key match)
        mapping_entries = mitre_mapping.get(alert_type) or mitre_mapping.get(
            alert_type.lower()
        )
        if not mapping_entries:
            logger.debug("No MITRE mapping found for alert_type %r — skipping.", alert_type)
            continue

        for technique in mapping_entries:
            technique_id = technique.get("id", "")
            if not technique_id:
                continue
            if technique_id in seen_ids:
                continue  # deduplicate by technique ID

            seen_ids.add(technique_id)
            techniques.append(
                {
                    "id": technique_id,
                    "name": technique.get("name", ""),
                    "tactic": technique.get("tactic", ""),
                }
            )

    return techniques
