"""
D2 Threat Intelligence — Dashboard metrics endpoint.
"""

from collections import defaultdict
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import Alert, Incident
from schemas import DashboardMetrics

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/metrics", response_model=DashboardMetrics)
def get_metrics(db: Session = Depends(get_db)) -> DashboardMetrics:
    """Return aggregated dashboard metrics."""
    # -----------------------------------------------------------------------
    # Alert counts
    # -----------------------------------------------------------------------
    all_alerts: List[Alert] = db.query(Alert).all()
    total_alerts = len(all_alerts)
    false_positives = sum(1 for a in all_alerts if a.is_false_positive)
    genuine_threats = total_alerts - false_positives

    # -----------------------------------------------------------------------
    # Incident counts
    # -----------------------------------------------------------------------
    all_incidents: List[Incident] = db.query(Incident).all()
    open_incidents = sum(1 for i in all_incidents if i.status == "open")

    # -----------------------------------------------------------------------
    # Severity distribution (incidents)
    # -----------------------------------------------------------------------
    severity_distribution: Dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    for incident in all_incidents:
        sev = incident.severity
        if sev in severity_distribution:
            severity_distribution[sev] += 1
        else:
            severity_distribution[sev] = 1

    # -----------------------------------------------------------------------
    # Alerts by source
    # -----------------------------------------------------------------------
    alerts_by_source: Dict[str, int] = defaultdict(int)
    for alert in all_alerts:
        alerts_by_source[alert.raw_source] += 1

    # -----------------------------------------------------------------------
    # Incidents by hour (based on incident created_at)
    # -----------------------------------------------------------------------
    hour_counts: Dict[str, int] = defaultdict(int)
    for incident in all_incidents:
        if incident.created_at:
            # Bucket by start of hour (HH:00)
            hour_key = incident.created_at.strftime("%H:00")
            hour_counts[hour_key] += 1

    incidents_by_hour: List[Dict[str, Any]] = [
        {"hour": hour, "count": count}
        for hour, count in sorted(hour_counts.items())
    ]

    return DashboardMetrics(
        total_alerts=total_alerts,
        genuine_threats=genuine_threats,
        false_positives=false_positives,
        open_incidents=open_incidents,
        severity_distribution=dict(severity_distribution),
        alerts_by_source=dict(alerts_by_source),
        incidents_by_hour=incidents_by_hour,
    )
