"""
FastAPI application for AgentShield.
The SDK owns all security logic; FastAPI only calls and exposes it.
Endpoints:
  GET  /health
  POST /check
  POST /authorize
  POST /execute (calls only registered fake sandbox tools)
  GET  /events
"""

import hmac
import os
import re
import secrets
import tempfile
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from agentshield import Shield, ExecutionStatus
from agentshield.audit import SQLiteAuditStore, redact_sensitive_data
from agentshield.review import SQLiteReviewStore
from agentshield.events import SQLiteEventStore
from agentshield.storage import create_stores, ConfigurationError
from agentshield.api.sessions import SqliteSessionStore, InMemorySessionStore, SessionManager
from agentshield.analyst import (
    SecurityAnalyst,
    LLMProvider,
    MockLLMProvider,
    GeminiProvider,
    AnalysisValidationError,
    ProviderError,
    ReportStore,
    SQLiteReportStore,
)
from agentshield.api.schemas import (
    HealthResponse,
    CheckRequest,
    AuthorizeRequest,
    ExecuteRequest,
    DecisionResponse,
    ExecutionResponse,
    EventsResponse,
    EventItem,
    PauseAgentRequest,
    ReviewActionRequest,
    AuditVerifyResponse,
    SecurityEventModel,
    SecurityEventsResponse,
    SecurityAlertModel,
    SecurityAlertsResponse,
    SecurityIncidentModel,
    SecurityIncidentsResponse,
    AnalysisRequest,
    AnalysisResponse,
    AnalysisReportsListResponse,
    AuthLoginRequest,
    AuthSessionResponse,
    OverviewStatsResponse,
    ScenarioModel,
    SimulationRunModel,
    SimulatorSummaryModel,
    BatchRunRequest,
    ReadinessResponse,
    IncidentTraceResponse,
    PolicyRuleItem,
    AgentPolicyDetail,
    ToolPolicyDetail,
    PoliciesResponse,
    RiskFactorItem,
    SeverityThresholds,
    RiskFactorsResponse,
    RuntimeConfigResponse,
)
from agentshield.observability import (
    sanitize_correlation_id,
    set_current_correlation_id,
    get_current_correlation_id,
    clear_current_correlation_id,
    get_operational_logger,
    get_metrics_collector,
    StructuredLogger,
    MetricsCollector,
)
from agentshield.simulator import (
    SimulatorService,
    SimulationStore,
    SqliteSimulationStore,
    InMemorySimulationStore,
    get_default_scenarios,
    get_scenario,
)


# Request size limiter middleware (caps request body size at 1MB default)
MAX_REQUEST_BODY_BYTES = int(os.environ.get("AGENTSHIELD_MAX_BODY_BYTES", 1024 * 1024))

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
            return Response(content="Request payload too large", status_code=413)
        return await call_next(request)


class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        raw_corr = request.headers.get("x-correlation-id") or request.headers.get("x-request-id")
        corr_id = sanitize_correlation_id(raw_corr)
        set_current_correlation_id(corr_id)
        request.state.correlation_id = corr_id
        try:
            response = await call_next(request)
            response.headers["x-correlation-id"] = corr_id
            return response
        finally:
            clear_current_correlation_id()

def create_app(
    audit_db_path: Optional[str] = None,
    admin_api_key: Optional[str] = None,
    read_only: Optional[bool] = None,
    review_db_path: Optional[str] = None,
    events_db_path: Optional[str] = None,
    reports_db_path: Optional[str] = None,
    sessions_db_path: Optional[str] = None,
    simulation_db_path: Optional[str] = None,
    event_store: Optional[Any] = None,
    report_store: Optional[Any] = None,
    analyst: Optional[SecurityAnalyst] = None,
    llm_provider: Optional[LLMProvider] = None,
    simulator: Optional[SimulatorService] = None,
) -> FastAPI:
    app = FastAPI(title="AgentShield API", version="0.1.0")

    # Request size limiter & correlation tracking middleware
    app.add_middleware(CorrelationMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)

    # CORS & Trusted Origins configuration
    # Canonical variable: AGENTSHIELD_CORS_ORIGINS (governs both CORS headers and CSRF origin verification)
    # Backward-compatible alias: AGENTSHIELD_TRUSTED_ORIGINS
    configured_origin_sources = []
    cors_env = os.environ.get("AGENTSHIELD_CORS_ORIGINS")
    trusted_env = os.environ.get("AGENTSHIELD_TRUSTED_ORIGINS")
    if cors_env:
        configured_origin_sources.append(cors_env)
    if trusted_env:
        configured_origin_sources.append(trusted_env)
    if not configured_origin_sources:
        configured_origin_sources.append("http://localhost:5173,http://127.0.0.1:5173")

    configured_origins = set()
    for src in configured_origin_sources:
        for orig in src.split(","):
            cleaned = orig.strip().rstrip("/")
            if cleaned:
                configured_origins.add(cleaned)
    configured_origins_list = sorted(configured_origins)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=configured_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Auth configuration & read-only flag from env or params
    configured_admin_key = admin_api_key or os.environ.get("AGENTSHIELD_ADMIN_KEY")
    is_read_only = read_only if read_only is not None else (
        (os.environ.get("AGENTSHIELD_READONLY") or os.environ.get("AGENTSHIELD_READ_ONLY") or "false").lower() in ("true", "1", "yes")
    )

    # Instantiate StoreBundle based on environment (SQLite default, PostgreSQL if configured)
    stores = create_stores(
        audit_db_path=audit_db_path,
        review_db_path=review_db_path,
        events_db_path=events_db_path,
        reports_db_path=reports_db_path,
        sessions_db_path=sessions_db_path,
        simulation_db_path=simulation_db_path,
    )

    audit_store = stores.audit_store
    review_store = stores.review_store
    event_store = stores.event_store if event_store is None else event_store
    if analyst is not None and analyst.event_store is not None:
        event_store = analyst.event_store

    report_store = stores.report_store if report_store is None else report_store
    if analyst is not None and getattr(analyst, "report_store", None) is not None:
        report_store = analyst.report_store

    session_store = stores.session_store
    simulation_store = stores.simulation_store
    sim_review_store = stores.sim_review_store
    sim_event_store = stores.sim_event_store

    session_secret = os.environ.get("AGENTSHIELD_SESSION_SECRET")
    session_manager = (
        SessionManager(admin_key=configured_admin_key, store=session_store, session_secret=session_secret)
        if configured_admin_key
        else None
    )

    rate_limiter = stores.rate_limiter
    from agentshield.reliability.config import ReliabilityConfig, parse_rate_limit
    from agentshield.reliability.circuit_breaker import CircuitBreakerOpenError
    rel_config = ReliabilityConfig.from_env()

    shield = Shield(
        audit_store=audit_store,
        review_store=review_store,
        event_store=event_store,
        reliability_config=rel_config,
        rate_limiter=rate_limiter,
    )
    sim_logger = StructuredLogger(name="agentshield.simulator")
    sim_metrics = MetricsCollector()
    sim_shield = Shield(
        audit_store=None,
        review_store=sim_review_store,
        event_store=sim_event_store,
        reliability_config=rel_config,
        rate_limiter=rate_limiter,
        logger=sim_logger,
        metrics_collector=sim_metrics,
    )

    simulator_service = simulator or SimulatorService(shield=sim_shield, store=simulation_store)

    analyst_provider_env = os.environ.get("AGENTSHIELD_ANALYST_PROVIDER", "").lower()
    gemini_key_env = os.environ.get("GEMINI_API_KEY")
    allow_mock_fallback = (
        (os.environ.get("AGENTSHIELD_ALLOW_MOCK_FALLBACK") or "false").lower() in ("true", "1", "yes")
    )
    is_production = (os.environ.get("AGENTSHIELD_ENV") or os.environ.get("ENVIRONMENT") or "development").lower() == "production"

    if analyst is not None:
        security_analyst = analyst
        if getattr(security_analyst, "event_store", None) is None:
            security_analyst.event_store = event_store
        if getattr(security_analyst, "report_store", None) is None:
            security_analyst.report_store = report_store
    elif llm_provider is not None:
        security_analyst = SecurityAnalyst(provider=llm_provider, event_store=event_store, report_store=report_store)
    elif analyst_provider_env == "gemini" or gemini_key_env:
        if not gemini_key_env:
            raise ProviderError("GEMINI_API_KEY is not configured for analyst provider 'gemini'")
        try:
            gemini_prov = GeminiProvider(api_key=gemini_key_env)
            security_analyst = SecurityAnalyst(provider=gemini_prov, event_store=event_store, report_store=report_store)
        except Exception as e:
            if allow_mock_fallback:
                security_analyst = SecurityAnalyst(provider=MockLLMProvider(), event_store=event_store, report_store=report_store)
            else:
                raise ProviderError(
                    f"Failed to initialize configured Gemini provider: {str(e)}. "
                    "Set AGENTSHIELD_ALLOW_MOCK_FALLBACK=true to permit mock analyst fallback."
                ) from e
    elif is_production and not allow_mock_fallback:
        raise ProviderError(
            "Production environment requires a configured LLM provider (set GEMINI_API_KEY or configure AGENTSHIELD_ALLOW_MOCK_FALLBACK=true)."
        )
    else:
        security_analyst = SecurityAnalyst(provider=MockLLMProvider(), event_store=event_store, report_store=report_store)

    shield.analyst = security_analyst

    # Register only FAKE sandbox tools (counter/no real I/O)
    sandbox_counters = {"create_order": 0, "search_product": 0, "get_product": 0}

    def fake_create_order(args):
        sandbox_counters["create_order"] += 1
        return {"order_id": f"ord_{sandbox_counters['create_order']}", "status": "created", "sandbox": True}

    def fake_search_product(args):
        sandbox_counters["search_product"] += 1
        return {"items": ["item1", "item2"], "count": 2, "sandbox": True}

    def fake_get_product(args):
        sandbox_counters["get_product"] += 1
        return {"id": args.get("product_id", "p1"), "price": 99.0, "sandbox": True}

    shield.registry.register("create_order", fake_create_order)
    shield.registry.register("search_product", fake_search_product)
    shield.registry.register("get_product", fake_get_product)

    sim_shield.registry.register("create_order", fake_create_order)
    sim_shield.registry.register("search_product", fake_search_product)
    sim_shield.registry.register("get_product", fake_get_product)

    # Attach to app state for testing inspection
    app.state.shield = shield
    app.state.sim_shield = sim_shield
    app.state.audit_store = audit_store
    app.state.review_store = review_store
    app.state.sim_review_store = sim_review_store
    app.state.event_store = event_store
    app.state.sim_event_store = sim_event_store
    app.state.report_store = report_store
    app.state.session_store = session_store
    app.state.session_manager = session_manager
    app.state.simulation_store = simulation_store
    app.state.simulator = simulator_service
    app.state.event_manager = getattr(shield, "event_manager", None)
    app.state.sim_event_manager = getattr(sim_shield, "event_manager", None)
    app.state.analyst = security_analyst
    app.state.sandbox_counters = sandbox_counters
    app.state.is_read_only = is_read_only
    app.state.storage_backend = stores.backend
    app.state.rate_limiter = rate_limiter
    app.state.reliability_config = rel_config

    # Rate limiters & abuse protection tracking
    public_rate_limits: Dict[str, List[float]] = {}
    analyst_rate_limits: Dict[str, List[float]] = {}

    def _validate_origin(request: Request) -> None:
        """Validate request origin against host and configured trusted origins."""
        origin = request.headers.get("origin")
        if not origin:
            referer = request.headers.get("referer")
            if referer:
                from urllib.parse import urlparse
                parsed = urlparse(referer)
                origin = f"{parsed.scheme}://{parsed.netloc}"
        if not origin:
            return

        host = request.headers.get("host") or ""
        trusted = {
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://test",
            "https://test",
        }
        if host:
            trusted.add(f"http://{host}")
            trusted.add(f"https://{host}")

        # Automatically trust all origins configured via canonical AGENTSHIELD_CORS_ORIGINS or legacy AGENTSHIELD_TRUSTED_ORIGINS
        trusted.update(configured_origins)

        norm_origin = origin.rstrip("/")
        is_trusted = norm_origin in trusted
        if not is_trusted and host.endswith(".vercel.app") and norm_origin.endswith(".vercel.app"):
            is_trusted = True

        if not is_trusted:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Untrusted request origin '{origin}'",
            )

    def _verify_csrf(request: Request) -> None:
        """Verify CSRF token for cookie-authenticated state-changing operations."""
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            _validate_origin(request)
            csrf_header = request.headers.get("x-csrf-token")
            csrf_cookie = request.cookies.get("agentshield_csrf")
            if not csrf_header or not csrf_cookie or not hmac.compare_digest(csrf_header, csrf_cookie):
                raise HTTPException(status_code=403, detail="Forbidden: CSRF token verification failed")

    def _verify_admin(request: Request) -> str:
        if not configured_admin_key:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Admin endpoints are disabled because AGENTSHIELD_ADMIN_KEY is not configured",
            )
        # 1. Direct header authentication (x-admin-key or Authorization: Bearer ...)
        auth_header = request.headers.get("x-admin-key") or request.headers.get("authorization", "").replace("Bearer ", "").strip()
        if auth_header and hmac.compare_digest(auth_header, configured_admin_key):
            return request.headers.get("x-admin-user", "admin")

        # 2. Secure signed cookie session
        session_token = request.cookies.get("agentshield_session")
        if session_token and session_manager:
            payload = session_manager.verify_token(session_token)
            if payload:
                # Cookie authentication requires CSRF verification for state mutations
                _verify_csrf(request)
                return payload.get("sub", "admin")

        raise HTTPException(status_code=401, detail="Unauthorized: Invalid administrative credentials")

    def _check_mutation_allowed():
        if is_read_only:
            raise HTTPException(status_code=403, detail="Forbidden: API is in read-only mode for incident controls")

    def _check_public_rate_limit(request: Request, max_requests: Optional[int] = None, window_seconds: Optional[float] = None) -> None:
        cfg_max, cfg_win = parse_rate_limit(rel_config.rate_limit_public)
        limit = max_requests if max_requests is not None else cfg_max
        window = window_seconds if window_seconds is not None else cfg_win
        client_ip = request.client.host if request.client else "unknown"
        key = f"api:public:{client_ip}"
        if rate_limiter is not None:
            res = rate_limiter.check(key, limit, window)
            if not res.allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests: Public API rate limit exceeded. Please slow down.",
                    headers=res.to_headers(),
                )
        else:
            now = time.time()
            timestamps = public_rate_limits.setdefault(client_ip, [])
            valid_timestamps = [t for t in timestamps if now - t < window]
            if not valid_timestamps:
                public_rate_limits.pop(client_ip, None)
            else:
                public_rate_limits[client_ip] = valid_timestamps
            if len(public_rate_limits.get(client_ip, [])) >= limit:
                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests: Public API rate limit exceeded. Please slow down.",
                )
            public_rate_limits.setdefault(client_ip, []).append(now)

    def _check_public_payload_size(request: Request, max_bytes: Optional[int] = None) -> None:
        limit = max_bytes if max_bytes is not None else rel_config.max_arguments_bytes
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > limit:
            limit_str = f"{limit // 1024}KB" if limit % 1024 == 0 else f"{limit}B"
            raise HTTPException(
                status_code=413,
                detail=f"Request entity too large: payload exceeds public limit of {limit_str}",
            )

    def _check_analyst_rate_limit(request: Request, max_requests: Optional[int] = None, window_seconds: Optional[float] = None) -> None:
        cfg_max, cfg_win = parse_rate_limit(rel_config.rate_limit_analyst)
        limit = max_requests if max_requests is not None else cfg_max
        window = window_seconds if window_seconds is not None else cfg_win
        client_ip = request.client.host if request.client else "unknown"
        key = f"api:analyst:{client_ip}"
        if rate_limiter is not None:
            res = rate_limiter.check(key, limit, window)
            if not res.allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests: Analyst report generation rate limit exceeded. Please retry later.",
                    headers=res.to_headers(),
                )
        else:
            now = time.time()
            timestamps = analyst_rate_limits.setdefault(client_ip, [])
            analyst_rate_limits[client_ip] = [t for t in timestamps if now - t < window]
            if len(analyst_rate_limits[client_ip]) >= limit:
                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests: Analyst report generation rate limit exceeded. Please retry later.",
                )
            analyst_rate_limits[client_ip].append(now)

    ALLOWED_PUBLIC_SANDBOX_TOOLS = {"create_order", "search_product", "get_product"}

    # Authentication & Session Endpoints
    @app.post("/api/auth/login", response_model=Dict[str, Any])
    def auth_login(req: AuthLoginRequest, response: Response):
        if not configured_admin_key:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Admin authentication is disabled because AGENTSHIELD_ADMIN_KEY is not configured",
            )
        if not hmac.compare_digest(req.admin_key, configured_admin_key):
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid administrative credentials")

        token, expires_at = session_manager.create_session("admin")
        csrf_token = secrets.token_hex(24)

        response.set_cookie(
            key="agentshield_session",
            value=token,
            httponly=True,
            samesite="lax",
            secure=is_production,
            path="/",
            max_age=86400,
        )
        response.set_cookie(
            key="agentshield_csrf",
            value=csrf_token,
            httponly=False,
            samesite="lax",
            secure=is_production,
            path="/",
            max_age=86400,
        )
        return {
            "status": "authenticated",
            "authenticated": True,
            "expires_at": expires_at,
            "csrf_token": csrf_token,
            "read_only": is_read_only,
        }

    @app.post("/api/auth/logout")
    def auth_logout(request: Request, response: Response):
        token = request.cookies.get("agentshield_session")
        if token and session_manager:
            session_manager.revoke_token(token)
        response.delete_cookie(key="agentshield_session", path="/")
        response.delete_cookie(key="agentshield_csrf", path="/")
        return {"status": "logged_out", "authenticated": False, "read_only": is_read_only}

    @app.get("/api/auth/session", response_model=AuthSessionResponse)
    def auth_session(request: Request):
        if not configured_admin_key:
            return AuthSessionResponse(authenticated=False, read_only=is_read_only, admin_configured=False, expires_at=None, csrf_token=None)
        auth_header = request.headers.get("x-admin-key") or request.headers.get("authorization", "").replace("Bearer ", "").strip()
        if auth_header and hmac.compare_digest(auth_header, configured_admin_key):
            return AuthSessionResponse(authenticated=True, read_only=is_read_only, admin_configured=True, expires_at=None, csrf_token=None)
        token = request.cookies.get("agentshield_session")
        if token and session_manager:
            payload = session_manager.verify_token(token)
            if payload:
                csrf_token = request.cookies.get("agentshield_csrf")
                return AuthSessionResponse(
                    authenticated=True,
                    read_only=is_read_only,
                    admin_configured=True,
                    expires_at=payload.get("exp"),
                    csrf_token=csrf_token,
                )
        return AuthSessionResponse(authenticated=False, read_only=is_read_only, admin_configured=True, expires_at=None, csrf_token=None)

    # Overview & Statistics Endpoint (public live summary)
    @app.get("/api/overview", response_model=OverviewStatsResponse)
    @app.get("/api/stats", response_model=OverviewStatsResponse)
    def get_overview_stats():
        records = audit_store.query(limit=500)
        allow_count = sum(1 for r in records if r.decision == "ALLOW")
        review_count = sum(1 for r in records if r.decision == "REVIEW")
        block_count = sum(1 for r in records if r.decision == "BLOCK")
        pending_reviews = shield.get_review_queue()
        active_incidents = 0
        if getattr(shield, "event_manager", None):
            open_inc = shield.event_manager.store.query_incidents(status="open", limit=100)
            active_incidents = len(open_inc)
        return OverviewStatsResponse(
            total_evaluated=len(records),
            allow_count=allow_count,
            review_count=review_count,
            block_count=block_count,
            pending_reviews_count=len(pending_reviews),
            paused_agents=sorted(list(shield._paused_agents)),
            active_incidents_count=active_incidents,
            is_read_only=is_read_only,
            is_live=True,
            allow=allow_count,
            review=review_count,
            block=block_count,
            total=len(records),
        )

    @app.get("/health", response_model=HealthResponse)
    @app.get("/api/health", response_model=HealthResponse)
    def health():
        return HealthResponse(
            status="healthy",
            version="0.1.0",
            engine="AgentShield Runtime",
            read_only=is_read_only,
        )

    @app.get("/health/readiness", response_model=ReadinessResponse)
    @app.get("/api/health/readiness", response_model=ReadinessResponse)
    def readiness(request: Request):
        # Determine if caller has administrative privileges
        is_admin_caller = False
        if configured_admin_key:
            auth_header = request.headers.get("x-admin-key") or request.headers.get("authorization", "").replace("Bearer ", "").strip()
            if auth_header and hmac.compare_digest(auth_header, configured_admin_key):
                is_admin_caller = True
            elif session_manager and request.cookies.get("agentshield_session"):
                try:
                    payload = session_manager.verify_token(request.cookies.get("agentshield_session"))
                    if payload:
                        is_admin_caller = True
                except Exception:
                    pass

        # Check critical storage dependencies
        db_status = "connected"
        audit_status = "accessible"
        review_status = "accessible"
        event_status = "accessible"
        is_ready = True
        admin_error_reasons = []

        try:
            audit_store.query(limit=1)
        except Exception as e:
            audit_status = "inaccessible"
            is_ready = False
            admin_error_reasons.append(f"Audit store check failed: {type(e).__name__}: {redact_sensitive_data(str(e))}")

        try:
            shield.get_review_queue()
        except Exception as e:
            review_status = "inaccessible"
            is_ready = False
            admin_error_reasons.append(f"Review store check failed: {type(e).__name__}: {redact_sensitive_data(str(e))}")

        try:
            if getattr(shield, "event_manager", None):
                shield.event_manager.query_events(limit=1)
        except Exception as e:
            event_status = "inaccessible"
            is_ready = False
            admin_error_reasons.append(f"Event store check failed: {type(e).__name__}: {redact_sensitive_data(str(e))}")

        analyst_prov = "none"
        cb_state = "closed"
        if getattr(shield, "analyst", None) and getattr(shield.analyst, "provider", None):
            prov = shield.analyst.provider
            analyst_prov = getattr(prov, "model_name", type(prov).__name__)
            if hasattr(prov, "circuit_breaker") and prov.circuit_breaker:
                cb_state = prov.circuit_breaker.state.value

        if not is_ready:
            db_status = "disconnected"
            # Public/unauthenticated callers receive a generic degraded status without infrastructure details
            if not is_admin_caller:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "status": "degraded",
                        "database": db_status,
                        "message": "Service degraded. Critical dependency check failed.",
                    },
                )
            # Authenticated administrators receive sanitized diagnostic details
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "degraded",
                    "database": db_status,
                    "storage_backend": stores.backend,
                    "audit_store": audit_status,
                    "review_store": review_status,
                    "event_store": event_status,
                    "analyst_provider": analyst_prov,
                    "circuit_breaker": cb_state,
                    "read_only": is_read_only,
                    "errors": admin_error_reasons,
                },
            )

        return ReadinessResponse(
            status="ready",
            database=db_status,
            storage_backend=stores.backend,
            audit_store=audit_status,
            review_store=review_status,
            event_store=event_status,
            analyst_provider=analyst_prov,
            circuit_breaker=cb_state,
            read_only=is_read_only,
        )

    @app.get("/metrics")
    @app.get("/api/metrics")
    def get_metrics(request: Request, format: Optional[str] = None):
        _check_public_rate_limit(request)
        require_auth = (os.environ.get("AGENTSHIELD_REQUIRE_AUTH_FOR_METRICS") or "false").lower() in ("true", "1", "yes")
        if require_auth:
            _verify_admin(request)
        accept_header = request.headers.get("accept", "")
        collector = getattr(shield, "metrics_collector", None) or get_metrics_collector()
        if format == "prometheus" or "text/plain" in accept_header:
            return Response(content=collector.to_prometheus_text(), media_type="text/plain; version=0.0.4")
        return collector.get_snapshot()

    @app.get("/api/observability/logs")
    def get_observability_logs(
        request: Request,
        limit: int = 100,
        component: Optional[str] = None,
        event_name: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ):
        _verify_admin(request)
        if correlation_id and not re.match(r"^[a-zA-Z0-9_\-\.:]{1,128}$", correlation_id):
            raise HTTPException(status_code=400, detail="Invalid correlation_id format")
        logger_inst = getattr(shield, "logger", None) or get_operational_logger()
        safe_limit = max(1, min(limit, 500))
        logs = logger_inst.get_recent_logs(
            limit=safe_limit,
            component=component,
            event_name=event_name,
            correlation_id=correlation_id,
        )
        return {"logs": logs, "total": len(logs)}

    @app.post("/check", response_model=DecisionResponse)
    @app.post("/api/check", response_model=DecisionResponse)
    def check_input(req: CheckRequest, request: Request):
        _check_public_payload_size(request)
        _check_public_rate_limit(request)
        corr_id = request.headers.get("x-correlation-id") or getattr(request.state, "correlation_id", None)
        decision = shield.check(req.text, correlation_id=corr_id)
        return DecisionResponse(
            allowed=decision.allowed,
            decision=decision.decision.value,
            reasons=decision.reasons,
            risk_score=float(decision.risk_score),
            severity=decision.severity.value,
            agent=decision.agent,
            tool=decision.tool,
            correlation_id=decision.correlation_id,
            trace_id=decision.trace_id,
        )

    @app.post("/authorize", response_model=DecisionResponse)
    @app.post("/api/authorize", response_model=DecisionResponse)
    def authorize_action(req: AuthorizeRequest, request: Request):
        _check_public_payload_size(request)
        _check_public_rate_limit(request)
        corr_id = (
            req.arguments.get("correlation_id")
            if isinstance(req.arguments, dict) and "correlation_id" in req.arguments
            else request.headers.get("x-correlation-id") or getattr(request.state, "correlation_id", None)
        )
        decision = shield.authorize(
            agent=req.agent,
            tool=req.tool,
            arguments=req.arguments,
            permissions=req.permissions,
            correlation_id=corr_id,
        )
        return DecisionResponse(
            allowed=decision.allowed,
            decision=decision.decision.value,
            reasons=decision.reasons,
            risk_score=float(decision.risk_score),
            severity=decision.severity.value,
            agent=decision.agent,
            tool=decision.tool,
            correlation_id=decision.correlation_id,
            trace_id=decision.trace_id,
        )

    @app.post("/execute", response_model=ExecutionResponse)
    @app.post("/api/execute", response_model=ExecutionResponse)
    def execute_action(req: ExecuteRequest, request: Request):
        _check_public_payload_size(request)
        _check_public_rate_limit(request)
        if req.tool not in ALLOWED_PUBLIC_SANDBOX_TOOLS:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Tool '{req.tool}' is not an authorized public sandbox tool",
            )
        corr_id = (
            req.arguments.get("correlation_id")
            if isinstance(req.arguments, dict) and "correlation_id" in req.arguments
            else request.headers.get("x-correlation-id") or getattr(request.state, "correlation_id", None)
        )
        res = shield.execute(
            agent=req.agent,
            tool=req.tool,
            arguments=req.arguments,
            permissions=req.permissions,
            correlation_id=corr_id,
        )
        dec_resp = DecisionResponse(
            allowed=res.decision.allowed,
            decision=res.decision.decision.value,
            reasons=res.decision.reasons,
            risk_score=float(res.decision.risk_score),
            severity=res.decision.severity.value,
            agent=res.decision.agent,
            tool=res.decision.tool,
            correlation_id=res.decision.correlation_id,
            trace_id=res.decision.trace_id,
        )
        return ExecutionResponse(
            decision=dec_resp,
            execution_status=res.execution_status.value,
            tool_result=res.tool_result,
            error=res.error,
            correlation_id=res.decision.correlation_id,
            trace_id=res.decision.trace_id,
        )

    @app.get("/events", response_model=EventsResponse)
    def list_events_public(
        decision: Optional[str] = None,
        agent: Optional[str] = None,
        tool: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 50,
    ):
        records = audit_store.query(
            decision=decision,
            agent=agent,
            tool=tool,
            correlation_id=correlation_id,
            limit=limit,
        )
        items = [
            EventItem(
                id=r.id or 0,
                timestamp=r.timestamp,
                agent=r.agent,
                tool=r.tool,
                arguments=r.arguments,
                decision=r.decision,
                allowed=r.allowed,
                reasons=r.reasons,
                rules_triggered=r.rules_triggered,
                risk_score=r.risk_score,
                severity=r.severity,
                execution_status=r.execution_status,
                error=r.error,
                policy_version_hash=r.policy_version_hash,
                prev_hash=r.prev_hash,
                record_hash=r.record_hash,
                correlation_id=r.correlation_id,
                trace_id=r.trace_id,
            )
            for r in records
        ]
        return EventsResponse(events=items, total=len(items))

    @app.get("/api/events", response_model=EventsResponse)
    @app.get("/api/audit/events", response_model=EventsResponse)
    def list_events_admin(
        request: Request,
        decision: Optional[str] = None,
        agent: Optional[str] = None,
        tool: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 50,
    ):
        _verify_admin(request)
        records = audit_store.query(
            decision=decision,
            agent=agent,
            tool=tool,
            correlation_id=correlation_id,
            limit=limit,
        )
        items = [
            EventItem(
                id=r.id or 0,
                timestamp=r.timestamp,
                agent=r.agent,
                tool=r.tool,
                arguments=r.arguments,
                decision=r.decision,
                allowed=r.allowed,
                reasons=r.reasons,
                rules_triggered=r.rules_triggered,
                risk_score=r.risk_score,
                severity=r.severity,
                execution_status=r.execution_status,
                error=r.error,
                policy_version_hash=r.policy_version_hash,
                prev_hash=r.prev_hash,
                record_hash=r.record_hash,
                correlation_id=r.correlation_id,
                trace_id=r.trace_id,
            )
            for r in records
        ]
        return EventsResponse(events=items, total=len(items))

    @app.get("/audit/verify", response_model=AuditVerifyResponse)
    @app.get("/api/audit/verify", response_model=AuditVerifyResponse)
    def verify_audit_integrity(request: Request):
        _verify_admin(request)
        try:
            res = audit_store.verify_integrity()
            return AuditVerifyResponse(
                valid=bool(res.get("valid", False)),
                total_records=int(res.get("total_records", 0)),
                error=res.get("error"),
                corrupted_record_id=res.get("corrupted_record_id") or res.get("broken_at_id"),
            )
        except Exception as e:
            return AuditVerifyResponse(
                valid=False,
                total_records=0,
                error=f"Audit verification error: {str(e)}",
                corrupted_record_id=None,
            )

    # Incident control endpoints
    @app.post("/incident/pause")
    @app.post("/api/incident/pause")
    def pause_agent(req: PauseAgentRequest, request: Request):
        actor = _verify_admin(request)
        _check_mutation_allowed()
        shield.pause_agent(req.agent, actor=actor)
        return {"agent": req.agent, "status": "paused"}

    @app.post("/incident/unpause")
    @app.post("/api/incident/unpause")
    def unpause_agent(req: PauseAgentRequest, request: Request):
        actor = _verify_admin(request)
        _check_mutation_allowed()
        shield.unpause_agent(req.agent, actor=actor)
        return {"agent": req.agent, "status": "active"}

    @app.get("/incident/agents")
    @app.get("/api/incident/agents")
    def list_agents():
        return {"paused_agents": sorted(list(shield._paused_agents))}

    @app.get("/policies", response_model=PoliciesResponse)
    @app.get("/api/policies", response_model=PoliciesResponse)
    def get_policies(request: Request):
        _verify_admin(request)
        policy_cfg = shield.policy_engine.config
        known_tools = sorted(list(shield.policy_engine.known_tools))
        version_hash = shield.policy_engine.version_hash

        agents_list = []
        for ag_name, ag_cfg in sorted(policy_cfg.agents.items()):
            agents_list.append(AgentPolicyDetail(
                name=ag_cfg.name,
                allowed_tools=sorted(list(ag_cfg.allowed_tools or [])),
                denied_tools=sorted(list(ag_cfg.denied_tools or [])),
                allowed_destinations=sorted(list(ag_cfg.allowed_destinations or [])),
            ))

        tools_list = []
        for tool_name, tool_rule in sorted(policy_cfg.tools.items()):
            max_qty = tool_rule.max_quantity if tool_rule.max_quantity != float("inf") else None
            max_amt = tool_rule.max_amount if tool_rule.max_amount != float("inf") else None
            tools_list.append(ToolPolicyDetail(
                tool=tool_rule.tool,
                max_quantity=max_qty,
                max_amount=max_amt,
                required_permissions=sorted(list(tool_rule.required_permissions or [])),
                allowed_destinations=sorted(list(tool_rule.allowed_destinations or [])),
            ))

        policy_items = []
        for ag_cfg in agents_list:
            allowed_str = ", ".join(ag_cfg.allowed_tools) if ag_cfg.allowed_tools else "none"
            denied_str = f" Denies: {', '.join(ag_cfg.denied_tools)}." if ag_cfg.denied_tools else ""
            policy_items.append(PolicyRuleItem(
                name=f"{ag_cfg.name} Tool Scope",
                target=ag_cfg.name,
                description=f"Allowed tools: {allowed_str}.{denied_str}",
                status="enforcing",
            ))

        for t_cfg in tools_list:
            conds = []
            if t_cfg.max_quantity is not None:
                conds.append(f"max_quantity <= {int(t_cfg.max_quantity) if t_cfg.max_quantity.is_integer() else t_cfg.max_quantity}")
            if t_cfg.max_amount is not None:
                conds.append(f"max_amount <= {int(t_cfg.max_amount) if t_cfg.max_amount.is_integer() else t_cfg.max_amount}")
            if t_cfg.required_permissions:
                conds.append(f"requires {t_cfg.required_permissions}")
            desc = f"Hard restrictions: {', '.join(conds)}." if conds else f"Registered tool {t_cfg.tool}."
            policy_items.append(PolicyRuleItem(
                name=f"{t_cfg.tool} Restriction",
                target=t_cfg.tool,
                description=desc,
                status="enforcing",
            ))

        policy_items.append(PolicyRuleItem(
            name="Unknown Tool Rejection",
            target="Global",
            description="Any tool unlisted in PolicyEngine.known_tools strictly evaluated as BLOCK.",
            status="enforcing",
        ))

        return PoliciesResponse(
            version_hash=version_hash,
            known_tools=known_tools,
            agents=agents_list,
            tools=tools_list,
            policies=policy_items,
        )

    @app.get("/risk/factors", response_model=RiskFactorsResponse)
    @app.get("/api/risk/factors", response_model=RiskFactorsResponse)
    def get_risk_factors(request: Request):
        _verify_admin(request)
        from agentshield.risk.engine import LOW_MAX, MEDIUM_MAX, HIGH_MAX
        raw_factors = shield.risk_engine.get_registered_factors()
        factors_list = []
        for idx, f in enumerate(raw_factors):
            factors_list.append(RiskFactorItem(
                id=f"rf-{idx + 1}",
                name=f.name,
                weight=f.weight,
                description=f.explanation,
            ))
        return RiskFactorsResponse(
            factors=factors_list,
            severity_thresholds=SeverityThresholds(
                low_max=LOW_MAX,
                medium_max=MEDIUM_MAX,
                high_max=HIGH_MAX,
            ),
        )

    @app.get("/config", response_model=RuntimeConfigResponse)
    @app.get("/api/config", response_model=RuntimeConfigResponse)
    def get_runtime_configuration(request: Request):
        """Returns non-secret runtime configuration and limits for authorized clients."""
        _verify_admin(request)
        model_name = None
        if getattr(shield, "analyst", None) and getattr(shield.analyst, "provider", None):
            prov = shield.analyst.provider
            model_name = getattr(prov, "model_name", type(prov).__name__)

        from agentshield.storage.config import get_database_url
        has_db = bool(get_database_url())

        return RuntimeConfigResponse(
            environment="production" if is_production else "development",
            read_only=is_read_only,
            storage_backend=stores.backend,
            database_configured=has_db,
            analyst_provider=analyst_provider_env or "mock",
            analyst_model=model_name,
            mock_fallback_enabled=allow_mock_fallback,
            max_tool_execution_seconds=rel_config.max_tool_execution_seconds,
            max_tool_calls_per_session=rel_config.max_tool_calls_per_session,
            max_arguments_bytes=rel_config.max_arguments_bytes,
            max_body_bytes=MAX_REQUEST_BODY_BYTES,
            max_token_budget=rel_config.max_token_budget,
            rate_limit_agent=rel_config.rate_limit_agent,
            rate_limit_tool=rel_config.rate_limit_tool,
            rate_limit_public=rel_config.rate_limit_public,
            rate_limit_analyst=rel_config.rate_limit_analyst,
            loop_consecutive_limit=rel_config.loop_consecutive_limit,
            loop_cycle_limit=rel_config.loop_cycle_limit,
            circuit_breaker_failure_threshold=rel_config.cb_failure_threshold,
            circuit_breaker_recovery_timeout=rel_config.cb_recovery_timeout,
            policy_version_hash=shield.policy_engine.version_hash,
            admin_auth_configured=bool(configured_admin_key),
        )

    @app.get("/reviews")
    @app.get("/api/reviews")
    @app.get("/incident/reviews")
    @app.get("/api/incident/reviews")
    def list_pending_reviews(request: Request, source: Optional[str] = None):
        _verify_admin(request)
        prod_reviews = [dict(r, simulated=False, is_simulated=False) for r in shield.get_review_queue()]
        sim_reviews = [dict(r, simulated=True, is_simulated=True) for r in sim_shield.get_review_queue()]

        if source == "production":
            return {"reviews": prod_reviews, "count": len(prod_reviews)}
        elif source == "simulation":
            return {"reviews": sim_reviews, "count": len(sim_reviews)}
        else:
            combined = prod_reviews + sim_reviews
            return {"reviews": combined, "count": len(combined)}

    @app.post("/incident/review")
    @app.post("/api/incident/review")
    def review_action(req: ReviewActionRequest, request: Request):
        actor = _verify_admin(request)
        _check_mutation_allowed()

        # Check simulator review queue first
        if sim_shield.review_store.get_review(req.review_id):
            if req.action.lower() == "approve":
                res = sim_shield.approve_review(req.review_id, approver=actor)
                if not res:
                    raise HTTPException(status_code=404, detail="Review request not found")
                return {
                    "status": "approved",
                    "execution_status": res.execution_status.value,
                    "result": res.tool_result,
                    "simulated": True,
                }
            else:
                dec = sim_shield.reject_review(req.review_id, reason=req.reason or "Rejected by reviewer", reviewer=actor)
                if not dec:
                    raise HTTPException(status_code=404, detail="Review request not found")
                return {
                    "status": "rejected",
                    "decision": dec.decision.value,
                    "simulated": True,
                }

        # Operational production review queue
        if req.action.lower() == "approve":
            res = shield.approve_review(req.review_id, approver=actor)
            if not res:
                raise HTTPException(status_code=404, detail="Review request not found")
            return {
                "status": "approved",
                "execution_status": res.execution_status.value,
                "result": res.tool_result,
                "simulated": False,
            }
        else:
            dec = shield.reject_review(req.review_id, reason=req.reason or "Rejected by reviewer", reviewer=actor)
            if not dec:
                raise HTTPException(status_code=404, detail="Review request not found")
            return {
                "status": "rejected",
                "decision": dec.decision.value,
                "simulated": False,
            }

    # Security Event, Alert, and Incident Management Endpoints (authenticated, read-only)
    @app.get("/api/security/events", response_model=SecurityEventsResponse)
    def list_security_events(
        request: Request,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        decision: Optional[str] = None,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ):
        _verify_admin(request)
        target_manager = sim_shield.event_manager if source == "simulation" else getattr(shield, "event_manager", None)
        if not target_manager:
            return SecurityEventsResponse(events=[], total=0)
        safe_limit = max(1, min(limit, 500))
        safe_offset = max(0, offset)
        events = target_manager.query_events(
            agent_id=agent_id,
            tool=tool,
            event_type=event_type,
            severity=severity,
            decision=decision,
            trace_id=trace_id,
            correlation_id=correlation_id,
            limit=safe_limit,
            offset=safe_offset,
        )
        items = [SecurityEventModel(**e.to_dict()) for e in events]
        return SecurityEventsResponse(events=items, total=len(items))

    @app.get("/api/security/events/{event_id}", response_model=SecurityEventModel)
    def get_security_event(event_id: str, request: Request):
        _verify_admin(request)
        if not getattr(shield, "event_manager", None):
            raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found")
        event = shield.event_manager.get_event(event_id)
        if not event:
            raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found")
        return SecurityEventModel(**event.to_dict())

    @app.get("/incident/alerts", response_model=SecurityAlertsResponse)
    @app.get("/api/incident/alerts", response_model=SecurityAlertsResponse)
    @app.get("/api/security/alerts", response_model=SecurityAlertsResponse)
    def list_security_alerts(
        request: Request,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        correlation_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ):
        _verify_admin(request)
        if not getattr(shield, "event_manager", None):
            return SecurityAlertsResponse(alerts=[], total=0)
        safe_limit = max(1, min(limit, 500))
        safe_offset = max(0, offset)
        alerts = shield.event_manager.query_alerts(
            status=status,
            severity=severity,
            agent_id=agent_id,
            alert_type=alert_type,
            correlation_id=correlation_id,
            incident_id=incident_id,
            limit=safe_limit,
            offset=safe_offset,
        )
        items = [SecurityAlertModel(**a.to_dict()) for a in alerts]
        return SecurityAlertsResponse(alerts=items, total=len(items))

    @app.get("/api/security/alerts/{alert_id}", response_model=SecurityAlertModel)
    def get_security_alert(alert_id: str, request: Request):
        _verify_admin(request)
        if not getattr(shield, "event_manager", None):
            raise HTTPException(status_code=404, detail=f"Security alert '{alert_id}' not found")
        alert = shield.event_manager.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail=f"Security alert '{alert_id}' not found")
        return SecurityAlertModel(**alert.to_dict())

    @app.get("/incident/incidents", response_model=SecurityIncidentsResponse)
    @app.get("/api/incident/incidents", response_model=SecurityIncidentsResponse)
    @app.get("/api/security/incidents", response_model=SecurityIncidentsResponse)
    def list_security_incidents(
        request: Request,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ):
        _verify_admin(request)
        if not getattr(shield, "event_manager", None):
            return SecurityIncidentsResponse(incidents=[], total=0)
        safe_limit = max(1, min(limit, 500))
        safe_offset = max(0, offset)
        incidents = shield.event_manager.store.query_incidents(
            status=status,
            severity=severity,
            agent_id=agent_id,
            correlation_id=correlation_id,
            limit=safe_limit,
            offset=safe_offset,
        )
        items = [SecurityIncidentModel(**i.to_dict()) for i in incidents]
        return SecurityIncidentsResponse(incidents=items, total=len(items))

    @app.get("/api/security/incidents/{incident_id}", response_model=SecurityIncidentModel)
    def get_security_incident(incident_id: str, request: Request):
        _verify_admin(request)
        if not re.match(r"^[a-zA-Z0-9_\-\.:]{1,128}$", incident_id):
            raise HTTPException(status_code=400, detail="Invalid incident_id format")
        if not getattr(shield, "event_manager", None):
            raise HTTPException(status_code=404, detail=f"Security incident '{incident_id}' not found")
        incident = shield.event_manager.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Security incident '{incident_id}' not found")
        return SecurityIncidentModel(**incident.to_dict())

    @app.get("/api/security/incidents/{incident_id}/trace", response_model=IncidentTraceResponse)
    def trace_security_incident(incident_id: str, request: Request):
        _verify_admin(request)
        if not re.match(r"^[a-zA-Z0-9_\-\.:]{1,128}$", incident_id):
            raise HTTPException(status_code=400, detail="Invalid incident_id format")
        if not getattr(shield, "event_manager", None):
            raise HTTPException(status_code=404, detail=f"Security incident '{incident_id}' not found")
        incident = shield.event_manager.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Security incident '{incident_id}' not found")

        # Correlated alerts
        alerts = shield.event_manager.query_alerts(incident_id=incident_id, limit=100)
        if not alerts and incident.correlation_id:
            alerts = shield.event_manager.query_alerts(correlation_id=incident.correlation_id, limit=100)

        # Correlated events
        events = []
        if incident.correlation_id:
            events = shield.event_manager.query_events(correlation_id=incident.correlation_id, limit=200)

        # Correlated audit records
        audit_records = []
        if incident.correlation_id:
            records = audit_store.query(correlation_id=incident.correlation_id, limit=200)
            audit_records = [
                EventItem(
                    id=r.id or 0,
                    timestamp=r.timestamp,
                    agent=r.agent,
                    tool=r.tool,
                    arguments=redact_sensitive_data(r.arguments or {}),
                    decision=r.decision,
                    allowed=r.allowed,
                    reasons=r.reasons,
                    rules_triggered=r.rules_triggered,
                    risk_score=r.risk_score,
                    severity=r.severity,
                    execution_status=r.execution_status,
                    error=redact_sensitive_data(r.error) if r.error else None,
                    policy_version_hash=r.policy_version_hash,
                    prev_hash=r.prev_hash,
                    record_hash=r.record_hash,
                    correlation_id=r.correlation_id,
                    trace_id=r.trace_id,
                )
                for r in records
            ]

        summary = {
            "incident_id": incident.incident_id,
            "correlation_id": incident.correlation_id,
            "agent_id": incident.agent_id,
            "severity": incident.severity,
            "status": incident.status,
            "total_alerts": len(alerts),
            "total_events": len(events),
            "total_audit_records": len(audit_records),
            "created_at": incident.created_at,
            "updated_at": incident.updated_at,
        }

        return IncidentTraceResponse(
            incident=SecurityIncidentModel(**incident.to_dict()),
            alerts=[SecurityAlertModel(**a.to_dict()) for a in alerts],
            events=[SecurityEventModel(**e.to_dict()) for e in events],
            audit_records=audit_records,
            summary=summary,
        )

    # LLM Security Analyst Endpoints (authenticated, read-only)
    @app.get("/incident/report/{incident_id}", response_model=AnalysisResponse)
    @app.get("/api/incident/report/{incident_id}", response_model=AnalysisResponse)
    @app.get("/api/security/incidents/{incident_id}/investigation", response_model=AnalysisResponse)
    def investigate_security_incident(incident_id: str, request: Request):
        _verify_admin(request)
        _check_analyst_rate_limit(request)
        if not re.match(r"^[a-zA-Z0-9_\-\.:]{1,128}$", incident_id):
            raise HTTPException(status_code=400, detail="Invalid incident_id format")
        if not security_analyst:
            raise HTTPException(status_code=503, detail="Security Analyst service is not configured")
        active_store = security_analyst.event_store or event_store
        if not active_store or not active_store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail=f"Security incident '{incident_id}' not found")

        try:
            report = security_analyst.investigate_incident(incident_id)
            return AnalysisResponse(report=report.to_dict())
        except HTTPException:
            raise
        except CircuitBreakerOpenError as e:
            raise HTTPException(
                status_code=503,
                detail=f"Service Unavailable: External LLM provider circuit breaker is OPEN ({str(e)})",
                headers={"Retry-After": str(max(1, int(e.retry_after)))},
            )
        except AnalysisValidationError as e:
            raise HTTPException(status_code=422, detail=f"Analysis validation error: {str(e)}")
        except ProviderError as e:
            raise HTTPException(status_code=502, detail=f"LLM Provider failure: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Analyst internal error: {str(e)}")

    @app.post("/incident/report", response_model=AnalysisResponse)
    @app.post("/api/incident/report", response_model=AnalysisResponse)
    @app.post("/api/security/analyst/analyze", response_model=AnalysisResponse)
    def analyze_security_incident(req: AnalysisRequest, request: Request):
        _verify_admin(request)
        _check_analyst_rate_limit(request)
        if not security_analyst:
            raise HTTPException(status_code=503, detail="Security Analyst service is not configured")

        try:
            if req.incident_id:
                if not re.match(r"^[a-zA-Z0-9_\-\.:]{1,128}$", req.incident_id):
                    raise HTTPException(status_code=400, detail="Invalid incident_id format")
                active_store = security_analyst.event_store or event_store
                if not active_store or not active_store.get_incident(req.incident_id):
                    raise HTTPException(status_code=404, detail=f"Security incident '{req.incident_id}' not found")
                report = security_analyst.investigate_incident(req.incident_id)
            elif req.correlation_id:
                if not re.match(r"^[a-zA-Z0-9_\-\.:]{1,128}$", req.correlation_id):
                    raise HTTPException(status_code=400, detail="Invalid correlation_id format")
                report = security_analyst.investigate_correlation(req.correlation_id)
            else:
                raise HTTPException(status_code=400, detail="Must provide either 'incident_id' or 'correlation_id'")
            return AnalysisResponse(report=report.to_dict())
        except HTTPException:
            raise
        except CircuitBreakerOpenError as e:
            raise HTTPException(
                status_code=503,
                detail=f"Service Unavailable: External LLM provider circuit breaker is OPEN ({str(e)})",
                headers={"Retry-After": str(max(1, int(e.retry_after)))},
            )
        except AnalysisValidationError as e:
            raise HTTPException(status_code=422, detail=f"Analysis validation error: {str(e)}")
        except ProviderError as e:
            raise HTTPException(status_code=502, detail=f"LLM Provider failure: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Analyst internal error: {str(e)}")

    # Persistent Investigation Report Retrieval & Listing Endpoints (authenticated, read-only)
    @app.get("/api/security/incidents/{incident_id}/reports", response_model=AnalysisReportsListResponse)
    def list_incident_reports(
        incident_id: str,
        request: Request,
        limit: int = 50,
        offset: int = 0,
    ):
        _verify_admin(request)
        active_report_store = getattr(security_analyst, "report_store", None) or report_store
        if not active_report_store:
            raise HTTPException(status_code=503, detail="Investigation Report store is not configured")

        active_event_store = getattr(security_analyst, "event_store", None) or event_store
        if active_event_store and not active_event_store.get_incident(incident_id):
            raise HTTPException(status_code=404, detail=f"Security incident '{incident_id}' not found")

        try:
            reports = active_report_store.list_reports_for_incident(incident_id, limit=limit, offset=offset)
            total_count = active_report_store.count_reports(incident_id=incident_id)
            return AnalysisReportsListResponse(
                reports=[r.to_dict() for r in reports],
                total=total_count,
            )
        except AnalysisValidationError as e:
            raise HTTPException(status_code=422, detail=f"Stored report validation error: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to retrieve incident reports: {str(e)}")

    @app.get("/api/security/reports/{report_id}", response_model=AnalysisResponse)
    def get_investigation_report(report_id: str, request: Request):
        _verify_admin(request)
        active_report_store = getattr(security_analyst, "report_store", None) or report_store
        if not active_report_store:
            raise HTTPException(status_code=503, detail="Investigation Report store is not configured")

        try:
            report = active_report_store.get_report(report_id)
            if not report:
                raise HTTPException(status_code=404, detail=f"Investigation report '{report_id}' not found")
            return AnalysisResponse(report=report.to_dict())
        except HTTPException:
            raise
        except AnalysisValidationError as e:
            raise HTTPException(status_code=422, detail=f"Stored report validation error: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to retrieve report: {str(e)}")

    @app.get("/api/security/reports", response_model=AnalysisReportsListResponse)
    def list_investigation_reports(
        request: Request,
        incident_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ):
        _verify_admin(request)
        active_report_store = getattr(security_analyst, "report_store", None) or report_store
        if not active_report_store:
            raise HTTPException(status_code=503, detail="Investigation Report store is not configured")

        try:
            reports = active_report_store.query_reports(
                incident_id=incident_id,
                correlation_id=correlation_id,
                limit=limit,
                offset=offset,
            )
            total_count = active_report_store.count_reports(
                incident_id=incident_id,
                correlation_id=correlation_id,
            )
            return AnalysisReportsListResponse(
                reports=[r.to_dict() for r in reports],
                total=total_count,
            )
        except AnalysisValidationError as e:
            raise HTTPException(status_code=422, detail=f"Stored report validation error: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to list reports: {str(e)}")

    # Attack Simulator Endpoints under /api/simulator namespace
    @app.get("/api/simulator/scenarios", response_model=List[ScenarioModel])
    def list_simulation_scenarios():
        scenarios = simulator_service.list_scenarios()
        return [ScenarioModel(**s.to_dict()) for s in scenarios]

    @app.get("/api/simulator/scenarios/{scenario_id}", response_model=ScenarioModel)
    def get_simulation_scenario(scenario_id: str):
        if not re.match(r"^[a-zA-Z0-9_\-]{1,64}$", scenario_id):
            raise HTTPException(status_code=400, detail="Invalid scenario_id format")
        scenario = simulator_service.get_scenario(scenario_id)
        if not scenario:
            raise HTTPException(status_code=404, detail=f"Simulation scenario '{scenario_id}' not found")
        return ScenarioModel(**scenario.to_dict())

    @app.post("/api/simulator/run/{scenario_id}", response_model=SimulationRunModel)
    def run_simulation_scenario(scenario_id: str, request: Request):
        _check_public_rate_limit(request)
        if not re.match(r"^[a-zA-Z0-9_\-]{1,64}$", scenario_id):
            raise HTTPException(status_code=400, detail="Invalid scenario_id format")
        try:
            run = simulator_service.execute_scenario(scenario_id)
            return SimulationRunModel(**run.to_dict())
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Simulation error: {str(e)}")

    @app.post("/api/simulator/run-batch", response_model=List[SimulationRunModel])
    def run_simulation_batch(req: BatchRunRequest, request: Request):
        _check_public_rate_limit(request)
        if req.scenario_ids and len(req.scenario_ids) > 20:
            raise HTTPException(status_code=400, detail="Batch size exceeds maximum limit of 20 scenarios")
        if req.scenario_ids:
            for sid in req.scenario_ids:
                if not re.match(r"^[a-zA-Z0-9_\-]{1,64}$", sid):
                    raise HTTPException(status_code=400, detail=f"Invalid scenario_id format: '{sid}'")
        try:
            runs = simulator_service.execute_batch(req.scenario_ids)
            return [SimulationRunModel(**r.to_dict()) for r in runs]
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Batch simulation error: {str(e)}")

    @app.get("/api/simulator/runs/{run_id}", response_model=SimulationRunModel)
    def get_simulation_run(run_id: str):
        if not re.match(r"^[a-zA-Z0-9_\-]{1,64}$", run_id):
            raise HTTPException(status_code=400, detail="Invalid run_id format")
        run = simulator_service.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Simulation run '{run_id}' not found")
        return SimulationRunModel(**run.to_dict())

    @app.get("/api/simulator/history", response_model=List[SimulationRunModel])
    def get_simulation_history(limit: int = 50, offset: int = 0):
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)
        runs = simulator_service.get_history(limit=safe_limit, offset=safe_offset)
        return [SimulationRunModel(**r.to_dict()) for r in runs]

    @app.get("/api/simulator/summary", response_model=SimulatorSummaryModel)
    @app.get("/api/simulator/benchmarks", response_model=SimulatorSummaryModel)
    def get_simulation_summary():
        summary = simulator_service.get_summary()
        return SimulatorSummaryModel(**summary.to_dict())

    @app.delete("/api/simulator/history")
    @app.post("/api/simulator/history/clear")
    def clear_simulation_history(request: Request):
        _verify_admin(request)
        _check_mutation_allowed()
        count = simulator_service.clear_history()
        return {"status": "cleared", "records_cleared": count}

    return app

app = create_app()
