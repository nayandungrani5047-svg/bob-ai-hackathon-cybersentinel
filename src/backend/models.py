"""
D2 Threat Intelligence — SQLAlchemy ORM models.

Incident is declared BEFORE Alert because Alert carries a FK to incidents.id.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
)

try:
    from .database import Base  # package import (tests, Docker)
except ImportError:
    from database import Base   # flat import (uvicorn main:app from backend/)


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)          # Critical / High / Medium / Low
    priority_score = Column(Float, nullable=False)     # 0-100
    priority_reasoning = Column(String, nullable=False)
    mitre_techniques = Column(String, nullable=False)  # JSON text array
    bluf = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open")
    alert_count = Column(Integer, nullable=False)
    sources = Column(String, nullable=True)          # JSON text list of source names
    correlation_rule = Column(String, nullable=True)  # attack_chain / same_ip_window / etc.
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    raw_source = Column(String, nullable=False)
    source_format = Column(String, nullable=False)     # siem / sensor / intel / feed
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String, nullable=False)
    dest_ip = Column(String, nullable=True)
    alert_type = Column(String, nullable=False)        # brute_force, lateral_movement, …
    description = Column(String, nullable=False)
    severity_raw = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    is_false_positive = Column(Boolean, nullable=False, default=False)
    fp_reason = Column(String, nullable=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True, index=True)
    extra_data = Column(String, nullable=True)         # JSON text
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
