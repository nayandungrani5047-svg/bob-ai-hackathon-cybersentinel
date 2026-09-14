"""
D2 Threat Intelligence — Alert endpoints.
"""

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from models import Alert, Incident
from schemas import AlertResponse

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _attach_mitre(alert: Alert, db: Session) -> AlertResponse:
    """Build an AlertResponse and populate mitre_techniques from the parent incident."""
    response = AlertResponse.model_validate(alert)
    if alert.incident_id:
        incident = db.query(Incident).filter(Incident.id == alert.incident_id).first()
        if incident and incident.mitre_techniques:
            try:
                response.mitre_techniques = json.loads(incident.mitre_techniques)
            except (ValueError, TypeError):
                response.mitre_techniques = []
    return response


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity_raw"),
    is_fp: Optional[bool] = Query(None, description="Filter by false-positive flag"),
    source: Optional[str] = Query(None, description="Filter by raw_source"),
    db: Session = Depends(get_db),
) -> List[AlertResponse]:
    """Return all alerts, with optional filters."""
    q = db.query(Alert)

    if severity is not None:
        q = q.filter(Alert.severity_raw.ilike(severity))
    if is_fp is not None:
        q = q.filter(Alert.is_false_positive == is_fp)
    if source is not None:
        q = q.filter(Alert.raw_source == source)

    alerts = q.order_by(Alert.timestamp.desc()).all()
    return [_attach_mitre(a, db) for a in alerts]


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> AlertResponse:
    """Return a single alert by ID, or 404."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return _attach_mitre(alert, db)
