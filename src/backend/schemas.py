"""
D2 Threat Intelligence — Pydantic v2 response schemas.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------
class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    raw_source: str
    source_format: str
    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    alert_type: str
    description: str
    severity_raw: str
    confidence: float
    is_false_positive: bool
    fp_reason: Optional[str] = None
    incident_id: Optional[str] = None
    extra_data: Optional[str] = None
    created_at: datetime

    # Populated by the endpoint when the parent incident is available
    mitre_techniques: List[Dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    severity: str
    priority_score: float
    priority_reasoning: str
    mitre_techniques: List[Dict[str, Any]] = []
    bluf: str
    status: str
    alert_count: int
    sources: List[str] = []
    correlation_rule: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @field_validator("mitre_techniques", mode="before")
    @classmethod
    def parse_mitre(cls, v: Any) -> List[Dict[str, Any]]:
        """Accept either a JSON string (from ORM) or an already-parsed list."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return []
        if v is None:
            return []
        return v

    @field_validator("sources", mode="before")
    @classmethod
    def parse_sources(cls, v: Any) -> List[str]:
        """Accept JSON string or list."""
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return []
        if v is None:
            return []
        return v


# ---------------------------------------------------------------------------
# Investigation (incident + correlated alerts + BLUF)
# ---------------------------------------------------------------------------
class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident: IncidentResponse
    alerts: List[AlertResponse]
    bluf: str


# ---------------------------------------------------------------------------
# Dashboard metrics
# ---------------------------------------------------------------------------
class DashboardMetrics(BaseModel):
    total_alerts: int
    genuine_threats: int
    false_positives: int
    open_incidents: int
    severity_distribution: Dict[str, int]
    alerts_by_source: Dict[str, int]
    incidents_by_hour: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Ingest response
# ---------------------------------------------------------------------------
class IngestResponse(BaseModel):
    message: str
    alerts_ingested: int
    incidents_created: int
    false_positives: int
