"""
D2 Threat Intelligence — Incident endpoints.
"""

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from models import Alert, Incident
from schemas import AlertResponse, IncidentResponse, InvestigationResponse

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _incident_response(incident: Incident) -> IncidentResponse:
    """Convert an ORM Incident to an IncidentResponse (handles JSON mitre_techniques)."""
    return IncidentResponse.model_validate(incident)


def _alert_response(alert: Alert, incident: Incident) -> AlertResponse:
    """Convert an ORM Alert to AlertResponse, populating mitre_techniques from its incident."""
    response = AlertResponse.model_validate(alert)
    if incident and incident.mitre_techniques:
        try:
            response.mitre_techniques = json.loads(incident.mitre_techniques)
        except (ValueError, TypeError):
            response.mitre_techniques = []
    return response


@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: Session = Depends(get_db),
) -> List[IncidentResponse]:
    """Return all incidents sorted by priority_score descending."""
    q = db.query(Incident)

    if severity is not None:
        q = q.filter(Incident.severity.ilike(severity))

    incidents = q.order_by(Incident.priority_score.desc()).all()
    return [_incident_response(inc) for inc in incidents]


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> IncidentResponse:
    """Return a single incident by ID, or 404."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return _incident_response(incident)


@router.get("/{incident_id}/investigation", response_model=InvestigationResponse)
def get_investigation(incident_id: str, db: Session = Depends(get_db)) -> InvestigationResponse:
    """Return the full investigation payload for an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    alerts = (
        db.query(Alert)
        .filter(Alert.incident_id == incident_id)
        .order_by(Alert.timestamp.asc())
        .all()
    )

    alert_responses = [_alert_response(a, incident) for a in alerts]

    return InvestigationResponse(
        incident=_incident_response(incident),
        alerts=alert_responses,
        bluf=incident.bluf,
    )
