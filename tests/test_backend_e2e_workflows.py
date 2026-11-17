"""
Phase 4: Backend End-to-End Integration and Workflow Verification Suite.

Exercises complete user-facing workflows through FastAPI ASGI test clients
with isolated temporary databases, verifying:
1. Public dashboard health & overview retrieval.
2. Admin login and authenticated session retrieval.
3. Simulator scenario listing and individual execution.
4. Batch execution containing ALLOW, REVIEW, and BLOCK outcomes.
5. Retrieval of simulation results and history.
6. Failed simulation handling without fabricated BLOCK decisions.
7. Review queue visibility and approval/rejection behavior.
8. Incident and security event retrieval.
9. Audit verification.
10. Logout and session invalidation.
11. Read-only mode preventing prohibited mutations.
12. CSRF and unauthorized-access protections.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from agentshield.api.app import create_app
from agentshield.simulator.service import SimulatorService
from agentshield.simulator.store import InMemorySimulationStore


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    """Provides an isolated test application with temporary SQLite stores and admin auth configured."""
    admin_key = "e2e-test-admin-secret-key-42"
    monkeypatch.setenv("AGENTSHIELD_ADMIN_KEY", admin_key)

    db_dir = tmp_path / "e2e_db"
    db_dir.mkdir(exist_ok=True)
    audit_db = str(db_dir / "agentshield_audit.db")

    app = create_app(
        audit_db_path=audit_db,
        admin_api_key=admin_key,
        read_only=False,
    )
    return {"app": app, "admin_key": admin_key, "db_dir": db_dir}


@pytest.mark.anyio
async def test_workflow_01_public_dashboard_health_and_overview(app_env):
    """Workflow 1: Public dashboard health and overview retrieval."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health check
        res_health = await client.get("/health")
        assert res_health.status_code == 200
        health = res_health.json()
        assert health["status"] == "healthy"
        assert health["version"] == "0.2.0"
        assert health["read_only"] is False

        # 2. Overview statistics
        res_overview = await client.get("/api/overview")
        assert res_overview.status_code == 200
        overview = res_overview.json()
        assert "total_evaluated" in overview
        assert "allow_count" in overview
        assert "review_count" in overview
        assert "block_count" in overview
        assert "pending_reviews_count" in overview
        assert "is_read_only" in overview
        assert overview["is_read_only"] is False


@pytest.mark.anyio
async def test_workflow_02_admin_login_and_authenticated_session(app_env):
    """Workflow 2: Admin login and authenticated session retrieval."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Initial unauthenticated session check
        res_sess_pre = await client.get("/api/auth/session")
        assert res_sess_pre.status_code == 200
        assert res_sess_pre.json()["authenticated"] is False

        # Invalid login attempt -> 401
        res_fail = await client.post("/api/auth/login", json={"admin_key": "wrong-key"})
        assert res_fail.status_code == 401

        # Valid login attempt -> 200, sets cookies and returns csrf_token
        res_login = await client.post("/api/auth/login", json={"admin_key": app_env["admin_key"]})
        assert res_login.status_code == 200
        data_login = res_login.json()
        assert data_login["authenticated"] is True
        assert data_login["csrf_token"] is not None

        # Verify session cookies exist in client
        assert "agentshield_session" in client.cookies
        assert "agentshield_csrf" in client.cookies

        # Subsequent session check returns authenticated: True
        res_sess_post = await client.get("/api/auth/session")
        assert res_sess_post.status_code == 200
        data_sess = res_sess_post.json()
        assert data_sess["authenticated"] is True
        assert data_sess["expires_at"] is not None


@pytest.mark.anyio
async def test_workflow_03_simulator_scenario_listing_and_execution(app_env):
    """Workflow 3: Simulator scenario listing and execution."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. List scenarios (all 7 scenarios present)
        res_scenarios = await client.get("/api/simulator/scenarios")
        assert res_scenarios.status_code == 200
        scenarios = res_scenarios.json()
        assert len(scenarios) == 7
        scenario_ids = [s["id"] for s in scenarios]
        assert "scenario-benign-order" in scenario_ids
        assert "scenario-prompt-injection" in scenario_ids
        assert "scenario-suspicious-legitimate" in scenario_ids

        # 2. Run benign scenario -> ALLOW
        res_allow = await client.post("/api/simulator/run/scenario-benign-order")
        assert res_allow.status_code == 200
        run_allow = res_allow.json()
        assert run_allow["actual_decision"] == "ALLOW"
        assert run_allow["expected_decision"] == "ALLOW"
        assert run_allow["expectation_matched"] is True
        assert run_allow["latency_ms"] >= 0

        # 3. Run prompt injection scenario -> BLOCK
        res_block = await client.post("/api/simulator/run/scenario-prompt-injection")
        assert res_block.status_code == 200
        run_block = res_block.json()
        assert run_block["actual_decision"] == "BLOCK"
        assert run_block["expected_decision"] == "BLOCK"
        assert run_block["expectation_matched"] is True

        # 4. Run legitimate quote inquiry -> REVIEW
        res_review = await client.post("/api/simulator/run/scenario-suspicious-legitimate")
        assert res_review.status_code == 200
        run_review = res_review.json()
        assert run_review["actual_decision"] == "REVIEW"
        assert run_review["expected_decision"] == "REVIEW"
        assert run_review["expectation_matched"] is True
        assert run_review["risk_score"] == 65.0
        assert run_review["severity"] == "HIGH"


@pytest.mark.anyio
async def test_workflow_04_batch_execution_with_all_outcomes(app_env):
    """Workflow 4: Batch execution containing ALLOW, REVIEW, and BLOCK scenarios."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "scenario_ids": [
                "scenario-benign-order",
                "scenario-suspicious-legitimate",
                "scenario-prompt-injection",
            ]
        }
        res_batch = await client.post("/api/simulator/run-batch", json=payload)
        assert res_batch.status_code == 200
        runs = res_batch.json()
        assert len(runs) == 3

        decisions = [r["actual_decision"] for r in runs]
        assert decisions == ["ALLOW", "REVIEW", "BLOCK"]
        for r in runs:
            assert r["expectation_matched"] is True


@pytest.mark.anyio
async def test_workflow_05_simulation_results_history_and_benchmarks(app_env):
    """Workflow 5: Retrieval of simulation results and history."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Run a scenario
        res_run = await client.post("/api/simulator/run/scenario-benign-order")
        assert res_run.status_code == 200
        run_id = res_run.json()["run_id"]

        # Fetch specific run
        res_get = await client.get(f"/api/simulator/runs/{run_id}")
        assert res_get.status_code == 200
        assert res_get.json()["run_id"] == run_id

        # Fetch history
        res_hist = await client.get("/api/simulator/history?limit=10")
        assert res_hist.status_code == 200
        hist = res_hist.json()
        assert any(item["run_id"] == run_id for item in hist)

        # Fetch benchmarks summary
        res_bench = await client.get("/api/simulator/benchmarks")
        assert res_bench.status_code == 200
        bench = res_bench.json()
        assert bench["total_runs"] >= 1
        assert bench["allow_count"] >= 1
        assert bench["expectation_match_rate"] == 100.0


@pytest.mark.anyio
async def test_workflow_06_failed_simulation_handling_without_fabricated_block(tmp_path):
    """Workflow 6: Failed simulation handling without fabricated BLOCK decisions."""
    # Build app with CrashingShield
    class CrashingShield:
        def execute(self, *args, **kwargs):
            raise RuntimeError("Database pool connection timed out: token=abc123secret")

    store = InMemorySimulationStore()
    sim_service = SimulatorService(shield=CrashingShield(), store=store)

    app = create_app(audit_db_path=":memory:", simulator=sim_service)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/simulator/run/scenario-benign-order")
        assert res.status_code == 200
        data = res.json()

        # Must report explicit FAILED status
        assert data["execution_status"] == "FAILED"
        # Must never report a synthetic BLOCK decision
        assert data["actual_decision"] is None
        assert data["actual_decision"] != "BLOCK"
        # Must not invent risk score or severity
        assert data["risk_score"] is None
        assert data["severity"] is None
        assert data["rules_triggered"] == []
        assert data["expectation_matched"] is False

        # Safe diagnostic without secrets
        assert "abc123secret" not in (data["error"] or "")
        assert "[REDACTED]" in (data["error"] or "")

        # Summary excludes failure from decisions, increments failed_runs
        res_bench = await client.get("/api/simulator/benchmarks")
        assert res_bench.status_code == 200
        bench = res_bench.json()
        assert bench["total_runs"] == 0
        assert bench["allow_count"] == 0
        assert bench["block_count"] == 0
        assert bench["failed_runs"] == 1
        assert bench["expectation_matches"] == 0


@pytest.mark.anyio
async def test_workflow_07_review_queue_visibility_and_approval(app_env):
    """Workflow 7: Review queue visibility and approval/rejection behavior."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Login as admin
        res_login = await client.post("/api/auth/login", json={"admin_key": app_env["admin_key"]})
        assert res_login.status_code == 200
        csrf_token = res_login.json()["csrf_token"]

        # Run legitimate inquiry that produces a pending REVIEW
        res_sim = await client.post("/api/simulator/run/scenario-suspicious-legitimate")
        assert res_sim.status_code == 200
        assert res_sim.json()["actual_decision"] == "REVIEW"

        # Check review queue
        res_reviews = await client.get("/incident/reviews")
        assert res_reviews.status_code == 200
        reviews = res_reviews.json().get("reviews", [])
        assert len(reviews) >= 1
        review_id = reviews[0]["review_id"]

        # Approve review with CSRF token
        headers = {"x-csrf-token": csrf_token}
        res_approve = await client.post(
            "/incident/review",
            json={
                "review_id": review_id,
                "action": "approve",
                "decision": "APPROVE",
                "reason": "E2E verification operator approval",
                "reviewer": "e2e-admin",
            },
            headers=headers,
        )
        assert res_approve.status_code == 200
        assert res_approve.json()["status"] == "approved"

        # Verify pending list is updated
        res_reviews_post = await client.get("/incident/reviews")
        assert res_reviews_post.status_code == 200
        reviews_post = res_reviews_post.json().get("reviews", [])
        assert not any(r["review_id"] == review_id for r in reviews_post)


@pytest.mark.anyio
async def test_workflow_08_incident_and_security_event_retrieval(app_env):
    """Workflow 8: Incident and security event retrieval."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Trigger tool execution to log to audit store
        res_exec = await client.post(
            "/execute",
            json={
                "agent": "shopping_agent",
                "tool": "get_product",
                "arguments": {"product_id": "p-101"},
            },
        )
        assert res_exec.status_code == 200

        # Retrieve events
        res_events = await client.get("/events?limit=20")
        assert res_events.status_code == 200
        events_data = res_events.json()
        assert "events" in events_data
        assert len(events_data["events"]) >= 1
        assert events_data["events"][0]["tool"] == "get_product"

        # Retrieve incidents list (authenticated)
        headers = {"x-admin-key": app_env["admin_key"]}
        res_incidents = await client.get("/incident/incidents", headers=headers)
        assert res_incidents.status_code == 200
        assert "incidents" in res_incidents.json()


@pytest.mark.anyio
async def test_workflow_09_audit_verification(app_env):
    """Workflow 9: Audit verification."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Execute tool proposal to generate audit record
        res_exec = await client.post(
            "/execute",
            json={
                "agent": "shopping_agent",
                "tool": "create_order",
                "arguments": {"product": "mouse", "quantity": 1},
            },
        )
        assert res_exec.status_code == 200

        # Verify cryptographic audit hash chain (requires admin credentials)
        headers = {"x-admin-key": app_env["admin_key"]}
        res_audit = await client.get("/api/audit/verify", headers=headers)
        assert res_audit.status_code == 200
        audit_data = res_audit.json()
        assert audit_data["valid"] is True
        assert audit_data["total_records"] >= 1


@pytest.mark.anyio
async def test_workflow_10_logout_and_session_invalidation(app_env):
    """Workflow 10: Logout and session invalidation."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login
        res_login = await client.post("/api/auth/login", json={"admin_key": app_env["admin_key"]})
        assert res_login.status_code == 200
        csrf_token = res_login.json()["csrf_token"]

        # 2. Logout with CSRF token
        headers = {"x-csrf-token": csrf_token}
        res_logout = await client.post("/api/auth/logout", headers=headers)
        assert res_logout.status_code == 200
        assert res_logout.json()["authenticated"] is False

        # 3. Check session -> now unauthenticated
        res_sess = await client.get("/api/auth/session")
        assert res_sess.status_code == 200
        assert res_sess.json()["authenticated"] is False

        # 4. Privileged administrative action -> 401
        res_priv = await client.delete("/api/simulator/history", headers=headers)
        assert res_priv.status_code == 401


@pytest.mark.anyio
async def test_workflow_11_readonly_mode_protection(tmp_path, monkeypatch):
    """Workflow 11: Read-only mode preventing prohibited mutations."""
    admin_key = "ro-test-admin-key"
    monkeypatch.setenv("AGENTSHIELD_ADMIN_KEY", admin_key)
    monkeypatch.setenv("AGENTSHIELD_READONLY", "1")

    app = create_app(audit_db_path=":memory:", admin_api_key=admin_key, read_only=True)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Safe demo reads succeed
        r_health = await client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["read_only"] is True

        r_overview = await client.get("/api/overview")
        assert r_overview.status_code == 200
        assert r_overview.json()["is_read_only"] is True

        # 2. Isolated simulator execution in sandbox succeeds
        r_sim = await client.post("/api/simulator/run/scenario-benign-order")
        assert r_sim.status_code == 200

        # 3. State mutations return 403 Forbidden even when authenticated
        headers = {"x-admin-key": admin_key}

        # Clear history mutation -> 403
        r_del = await client.delete("/api/simulator/history", headers=headers)
        assert r_del.status_code == 403
        assert "read-only mode" in r_del.json()["detail"].lower()

        # Pause agent mutation -> 403
        r_pause = await client.post("/incident/pause", json={"agent": "shopping_agent"}, headers=headers)
        assert r_pause.status_code == 403
        assert "read-only mode" in r_pause.json()["detail"].lower()


@pytest.mark.anyio
async def test_workflow_12_csrf_and_unauthorized_access_protections(app_env):
    """Workflow 12: CSRF and unauthorized-access protections."""
    transport = ASGITransport(app=app_env["app"])
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login to obtain session cookie
        res_login = await client.post("/api/auth/login", json={"admin_key": app_env["admin_key"]})
        assert res_login.status_code == 200
        csrf_token = res_login.json()["csrf_token"]

        # 2. Mutating request with session cookie BUT MISSING CSRF token -> 403
        res_no_csrf = await client.delete("/api/simulator/history")
        assert res_no_csrf.status_code == 403
        assert "csrf" in res_no_csrf.json()["detail"].lower()

        # 3. Mutating request with INVALID CSRF token -> 403
        res_bad_csrf = await client.delete(
            "/api/simulator/history",
            headers={"x-csrf-token": "completely-invalid-csrf-token"},
        )
        assert res_bad_csrf.status_code == 403
        assert "csrf" in res_bad_csrf.json()["detail"].lower()

        # 4. Mutating request with VALID CSRF token -> 200
        res_valid = await client.delete(
            "/api/simulator/history",
            headers={"x-csrf-token": csrf_token},
        )
        assert res_valid.status_code == 200
        assert res_valid.json()["status"] == "cleared"
