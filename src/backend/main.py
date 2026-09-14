"""
D2 Threat Intelligence — FastAPI application entry point.
"""

import json
import logging
import os
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import Alert, Incident
from schemas import IngestResponse
from routers import alerts as alerts_router
from routers import incidents as incidents_router
from routers import dashboard as dashboard_router
from pipeline import (
    normalise,
    classify_fps,
    correlate,
    prioritise,
    map_techniques,
    generate_bluf,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_HERE, "data")

# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="D2 Threat Intelligence API",
    description="Threat alert correlation and incident prioritisation service.",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# CORS — wide-open for demo purposes
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(alerts_router.router, prefix="/api")
app.include_router(incidents_router.router, prefix="/api")
app.include_router(dashboard_router.router, prefix="/api")

# ---------------------------------------------------------------------------
# Startup event
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event() -> None:
    os.makedirs(_DATA_DIR, exist_ok=True)
    Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["health"])
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Ingest endpoint
# ---------------------------------------------------------------------------
@app.post("/api/ingest", response_model=IngestResponse, tags=["pipeline"])
def ingest_alerts(db: Session = Depends(get_db)) -> IngestResponse:
    """
    Run the full ingest pipeline:
      load JSON → normalise → classify FP → correlate → prioritise
      → map MITRE → generate BLUF → persist to SQLite.
    """
    try:
        # ----------------------------------------------------------------
        # a. Load reference data files
        # ----------------------------------------------------------------
        with open(os.path.join(_DATA_DIR, "synthetic_alerts.json"), encoding="utf-8") as f:
            raw_alerts: list = json.load(f)

        with open(os.path.join(_DATA_DIR, "safe_ips.json"), encoding="utf-8") as f:
            safe_ips: list = json.load(f)

        with open(os.path.join(_DATA_DIR, "mitre_mapping.json"), encoding="utf-8") as f:
            mitre_mapping: dict = json.load(f)

        # ----------------------------------------------------------------
        # d. Clear existing data (alerts first due to FK constraint)
        # ----------------------------------------------------------------
        db.query(Alert).delete()
        db.query(Incident).delete()
        db.flush()

        # ----------------------------------------------------------------
        # e-f. Normalise then classify false positives
        # ----------------------------------------------------------------
        normalised = normalise(raw_alerts)
        classified = classify_fps(normalised, safe_ips)

        # ----------------------------------------------------------------
        # g. Correlate into incidents
        # ----------------------------------------------------------------
        incident_dicts = correlate(classified)

        # Build a lookup from alert_id → alert dict for fast access
        alert_by_id: dict[str, dict] = {a["id"]: a for a in classified}

        # ----------------------------------------------------------------
        # h. Prioritise, map MITRE, generate BLUF, and create ORM objects
        # ----------------------------------------------------------------
        orm_incidents: list[Incident] = []

        for inc_dict in incident_dicts:
            # Collect the correlated alert dicts for this incident
            correlated_alerts = [
                alert_by_id[aid]
                for aid in inc_dict.get("alert_ids", [])
                if aid in alert_by_id
            ]

            # Prioritise
            inc_dict = prioritise(inc_dict, classified)

            # Map MITRE techniques
            techniques = map_techniques(inc_dict.get("alert_types", []), mitre_mapping)

            # Generate BLUF
            bluf = generate_bluf(inc_dict, techniques, correlated_alerts)

            # Determine created_at from earliest alert timestamp
            timestamps = [
                a["timestamp"]
                for a in correlated_alerts
                if isinstance(a.get("timestamp"), datetime)
            ]
            created_at = min(timestamps) if timestamps else datetime.utcnow()

            # Create ORM Incident
            orm_incident = Incident(
                id=inc_dict["id"],
                title=inc_dict["title"],
                severity=inc_dict["severity"],
                priority_score=inc_dict["priority_score"],
                priority_reasoning=inc_dict["priority_reasoning"],
                mitre_techniques=json.dumps(techniques),
                bluf=bluf,
                status="open",
                alert_count=len(inc_dict.get("alert_ids", [])),
                sources=json.dumps(inc_dict.get("sources", [])),
                correlation_rule=inc_dict.get("correlation_rule"),
                created_at=created_at,
                updated_at=datetime.utcnow(),
            )
            db.add(orm_incident)
            orm_incidents.append(orm_incident)

            # Set incident_id on each alert dict
            for aid in inc_dict.get("alert_ids", []):
                if aid in alert_by_id:
                    alert_by_id[aid]["incident_id"] = inc_dict["id"]

        # ----------------------------------------------------------------
        # i. Persist all Alert ORM objects
        # ----------------------------------------------------------------
        # Flush incidents first so the FK constraint is satisfied
        db.flush()

        for alert_dict in classified:
            orm_alert = Alert(
                id=alert_dict["id"],
                raw_source=alert_dict["raw_source"],
                source_format=alert_dict["source_format"],
                timestamp=alert_dict["timestamp"],
                source_ip=alert_dict["source_ip"],
                dest_ip=alert_dict.get("dest_ip"),
                alert_type=alert_dict["alert_type"],
                description=alert_dict.get("description", ""),
                severity_raw=alert_dict["severity_raw"],
                confidence=float(alert_dict.get("confidence", 0.5)),
                is_false_positive=bool(alert_dict.get("is_false_positive", False)),
                fp_reason=alert_dict.get("fp_reason"),
                incident_id=alert_dict.get("incident_id"),
                extra_data=alert_dict.get("extra_data"),
                created_at=alert_dict.get("created_at", datetime.utcnow()),
            )
            db.add(orm_alert)

        # ----------------------------------------------------------------
        # j. Commit
        # ----------------------------------------------------------------
        db.commit()

        # ----------------------------------------------------------------
        # k. Build and return IngestResponse
        # ----------------------------------------------------------------
        total_alerts = len(classified)
        fp_count = sum(1 for a in classified if a.get("is_false_positive"))
        incidents_created = len(orm_incidents)

        logger.info(
            "Ingest complete: %d alerts, %d incidents, %d FPs.",
            total_alerts,
            incidents_created,
            fp_count,
        )

        return IngestResponse(
            message="Ingest complete.",
            alerts_ingested=total_alerts,
            incidents_created=incidents_created,
            false_positives=fp_count,
        )

    except Exception as exc:
        db.rollback()
        logger.exception("Ingest failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Ingest failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Reset endpoint
# ---------------------------------------------------------------------------
@app.delete("/api/reset", tags=["pipeline"])
def reset_database(db: Session = Depends(get_db)) -> dict:
    """Delete all alerts and incidents and return a confirmation message."""
    try:
        db.query(Alert).delete()
        db.query(Incident).delete()
        db.commit()
        return {"message": "Database cleared successfully"}
    except Exception as exc:
        db.rollback()
        logger.exception("Reset failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Reset failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Uvicorn entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
