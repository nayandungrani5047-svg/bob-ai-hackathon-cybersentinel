"""
Integration tests for the FastAPI application (main.py).

Uses FastAPI's TestClient backed by httpx.  A temporary SQLite file is used
so tests are fully isolated from the real app.db.

Strategy
--------
1. Before any import of ``main``, patch the ``database`` module to point at a
   temporary SQLite file (created once per test session via a session-scoped
   fixture).
2. Import ``main`` inside the fixture so it inherits the patched engine.
3. Use a fresh TestClient for every test class.  Between tests, DELETE+reset
   tables via the /api/reset endpoint or directly.
"""

import importlib
import json
import os
import sys
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Session-scoped test database setup
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_db_path(tmp_path_factory):
    """Create a temporary SQLite file that lives for the entire test session."""
    tmp_dir = tmp_path_factory.mktemp("testdb")
    return str(tmp_dir / "test_app.db")


@pytest.fixture(scope="session")
def app_client(test_db_path):
    """Build a patched FastAPI app and return a TestClient.

    This fixture:
    1. Patches ``database`` module to use the temp SQLite file.
    2. Imports (or reloads) ``main`` so it picks up the patched engine.
    3. Creates all tables.
    4. Returns a ``TestClient`` that is reused across all tests in the session.
    """
    import sqlalchemy
    from sqlalchemy.orm import sessionmaker

    # Build a new engine pointing at the temp file
    test_url = f"sqlite:///{test_db_path}"
    test_engine = sqlalchemy.create_engine(
        test_url,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Patch the database module BEFORE main imports it
    import database as db_module
    original_engine = db_module.engine
    original_session = db_module.SessionLocal
    db_module.engine = test_engine
    db_module.SessionLocal = TestSessionLocal

    # Force a clean import of main (and its sub-modules) using the patched DB
    for mod_name in list(sys.modules.keys()):
        if mod_name in ("main", "routers.alerts", "routers.incidents", "routers.dashboard"):
            del sys.modules[mod_name]

    import main as app_module

    # Create tables on test engine
    app_module.Base.metadata.create_all(bind=test_engine)

    from fastapi.testclient import TestClient
    client = TestClient(app_module.app)

    yield client, app_module, test_engine

    # Teardown — restore original DB (not strictly needed in tests but clean)
    db_module.engine = original_engine
    db_module.SessionLocal = original_session


@pytest.fixture(autouse=True)
def reset_between_tests(app_client):
    """Ensure database is empty before each test."""
    client, app_module, test_engine = app_client
    # Reset via endpoint (exercises the endpoint itself and ensures isolation)
    client.delete("/api/reset")
    yield


# ---------------------------------------------------------------------------
# Convenience accessor
# ---------------------------------------------------------------------------

@pytest.fixture
def client(app_client):
    return app_client[0]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHealthEndpoint:

    def test_health_endpoint(self, client):
        """GET /api/health → 200 {"status": "ok"}."""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestIngestEndpoint:

    def test_ingest_returns_200(self, client):
        """POST /api/ingest → 200 with expected response fields."""
        response = client.post("/api/ingest")
        assert response.status_code == 200, response.text

        body = response.json()
        assert "alerts_ingested" in body
        assert "incidents_created" in body
        assert "false_positives" in body
        assert body["alerts_ingested"] > 0

    def test_ingest_then_metrics(self, client):
        """After ingest, dashboard metrics should show positive counts."""
        ingest_resp = client.post("/api/ingest")
        assert ingest_resp.status_code == 200

        metrics_resp = client.get("/api/dashboard/metrics")
        assert metrics_resp.status_code == 200

        metrics = metrics_resp.json()
        assert metrics["total_alerts"] > 0
        assert metrics["genuine_threats"] > 0
        assert metrics["false_positives"] > 0

    def test_ingest_creates_incidents(self, client):
        """After ingest, GET /api/incidents → non-empty list."""
        client.post("/api/ingest")
        response = client.get("/api/incidents")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_ingest_is_idempotent(self, client):
        """Running ingest twice should replace data, not duplicate it."""
        r1 = client.post("/api/ingest")
        r2 = client.post("/api/ingest")

        assert r1.status_code == 200
        assert r2.status_code == 200

        # Alert counts must be identical between both runs
        assert r1.json()["alerts_ingested"] == r2.json()["alerts_ingested"]

        # DB reflects exactly one ingest worth of alerts
        metrics = client.get("/api/dashboard/metrics").json()
        assert metrics["total_alerts"] == r2.json()["alerts_ingested"]


class TestResetEndpoint:

    def test_reset_clears_data(self, client):
        """POST /api/ingest then DELETE /api/reset → metrics shows zeroes."""
        client.post("/api/ingest")

        reset_resp = client.delete("/api/reset")
        assert reset_resp.status_code == 200

        metrics = client.get("/api/dashboard/metrics").json()
        assert metrics["total_alerts"] == 0
        assert metrics["open_incidents"] == 0

    def test_reset_without_ingest_succeeds(self, client):
        """DELETE /api/reset on an already-empty DB must succeed."""
        response = client.delete("/api/reset")
        assert response.status_code == 200


class TestAlertsEndpoint:

    def test_alerts_list_empty_before_ingest(self, client):
        """GET /api/alerts before ingest → empty list."""
        response = client.get("/api/alerts")
        assert response.status_code == 200
        assert response.json() == []

    def test_alerts_list_populated_after_ingest(self, client):
        """GET /api/alerts after ingest → non-empty list."""
        client.post("/api/ingest")
        response = client.get("/api/alerts")
        assert response.status_code == 200
        assert len(response.json()) > 0

    def test_alert_detail(self, client):
        """GET /api/alerts/{id} → 200 with correct id."""
        client.post("/api/ingest")
        alerts = client.get("/api/alerts").json()
        assert len(alerts) > 0

        alert_id = alerts[0]["id"]
        detail = client.get(f"/api/alerts/{alert_id}")
        assert detail.status_code == 200
        assert detail.json()["id"] == alert_id

    def test_alert_detail_404(self, client):
        """GET /api/alerts/{id} with unknown id → 404."""
        response = client.get("/api/alerts/nonexistent-id")
        assert response.status_code == 404


class TestIncidentsEndpoint:

    def test_incidents_list_empty_before_ingest(self, client):
        """GET /api/incidents before ingest → empty list."""
        response = client.get("/api/incidents")
        assert response.status_code == 200
        assert response.json() == []

    def test_incident_detail(self, client):
        """GET /api/incidents/{id} → 200 for a valid ID."""
        client.post("/api/ingest")
        incidents = client.get("/api/incidents").json()
        assert len(incidents) > 0

        inc_id = incidents[0]["id"]
        detail = client.get(f"/api/incidents/{inc_id}")
        assert detail.status_code == 200
        assert detail.json()["id"] == inc_id

    def test_incident_detail_404(self, client):
        """GET /api/incidents/{id} with unknown id → 404."""
        response = client.get("/api/incidents/no-such-incident")
        assert response.status_code == 404

    def test_incident_investigation_endpoint(self, client):
        """GET /api/incidents/{id}/investigation → 200 with expected keys."""
        client.post("/api/ingest")
        incidents = client.get("/api/incidents").json()
        inc_id = incidents[0]["id"]

        inv = client.get(f"/api/incidents/{inc_id}/investigation")
        assert inv.status_code == 200

        body = inv.json()
        assert "incident" in body
        assert "alerts" in body
        assert "bluf" in body
