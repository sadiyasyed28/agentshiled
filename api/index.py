"""
Vercel entrypoint for AgentShield FastAPI backend.

Provides seamless ASGI routing for both production (Vercel Serverless) and
staging/preview environments (forwarding to Render staging backend with
PostgreSQL persistence, Host header normalization, and cold-start resilience).
"""

import gzip
import os
from pathlib import Path
import sys
import time
from typing import Dict
import urllib.error
import urllib.parse
import urllib.request
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# Add src to sys.path so agentshield package is discoverable
root_path = Path(__file__).resolve().parent.parent
src_path = root_path / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from agentshield.api.app import app as core_app

RENDER_STAGING_BACKEND = "https://agentshield-backend-staging.onrender.com"


def _is_staging_environment() -> bool:
    """Determines whether to proxy API calls to the Render staging backend."""
    env = (os.environ.get("AGENTSHIELD_ENV") or "").lower()
    if env == "staging":
        return True
    if env == "production":
        return False

    vercel_env = (os.environ.get("VERCEL_ENV") or "").lower()
    if vercel_env == "production":
        return False
    if vercel_env in ("preview", "development"):
        return True

    if os.environ.get("AGENTSHIELD_PROXY_STAGING") in ("1", "true", "yes"):
        return True

    vercel_branch = os.environ.get("VERCEL_GIT_COMMIT_REF", "")
    if vercel_branch in ("main", "master"):
        return False
    if vercel_branch.startswith("feature/") or vercel_branch.startswith("staging/"):
        return True

    # Branch inspection via local git repository
    try:
        import subprocess
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=str(root_path),
        )
        branch = res.stdout.strip()
        if branch in ("main", "master"):
            return False
        return "feature" in branch or "staging" in branch
    except Exception:
        # Default to production core app on unknown serverless runtimes
        return False


def create_staging_proxy_app() -> FastAPI:
    """Constructs a FastAPI proxy application forwarding requests to Render staging backend."""
    proxy = FastAPI(
        title="AgentShield Staging Gateway",
        description="Vercel ASGI proxy forwarding to Render staging backend with live PostgreSQL persistence",
        version="0.2.0",
    )

    @proxy.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
    async def proxy_to_render_staging(request: Request, full_path: str):
        target_url = f"{RENDER_STAGING_BACKEND}/{full_path}"
        if request.url.query:
            target_url += f"?{request.url.query}"

        # Normalize headers: override Host to Render domain to pass Cloudflare WAF validation
        req_headers: Dict[str, str] = {}
        for k, v in request.headers.items():
            if k.lower() not in ("host", "content-length", "transfer-encoding"):
                req_headers[k] = v
        req_headers["Host"] = "agentshield-backend-staging.onrender.com"
        if "host" in request.headers:
            req_headers["X-Forwarded-Host"] = request.headers["host"]
        req_headers["X-Forwarded-Proto"] = request.url.scheme or "https"

        body = await request.body()
        max_retries = 2 if request.method in ("GET", "HEAD", "OPTIONS") else 1

        for attempt in range(max_retries):
            upstream_req = urllib.request.Request(
                target_url,
                data=body if body else None,
                headers=req_headers,
                method=request.method,
            )
            try:
                with urllib.request.urlopen(upstream_req, timeout=30) as resp:
                    content = resp.read()
                    # Decompress gzip payload if needed
                    if resp.headers.get("Content-Encoding") == "gzip" or (len(content) > 2 and content[:2] == b"\x1f\x8b"):
                        try:
                            content = gzip.decompress(content)
                        except Exception:
                            pass

                    resp_headers: Dict[str, str] = {}
                    for hk, hv in resp.headers.items():
                        if hk.lower() not in ("content-encoding", "content-length", "transfer-encoding"):
                            resp_headers[hk] = hv

                    return Response(content=content, status_code=resp.status, headers=resp_headers)
            except urllib.error.HTTPError as e:
                content = e.read()
                # On transient 502/503 (e.g. Render spin-up cold start), pause briefly and retry
                if e.code in (502, 503) and attempt < max_retries - 1:
                    time.sleep(2)
                    continue

                if e.headers.get("Content-Encoding") == "gzip" or (len(content) > 2 and content[:2] == b"\x1f\x8b"):
                    try:
                        content = gzip.decompress(content)
                    except Exception:
                        pass

                resp_headers = {}
                for hk, hv in e.headers.items():
                    if hk.lower() not in ("content-encoding", "content-length", "transfer-encoding"):
                        resp_headers[hk] = hv

                return Response(content=content, status_code=e.code, headers=resp_headers)
            except Exception:
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue

        return JSONResponse(
            content={"status": "error", "detail": "Render staging backend unavailable during spin-up"},
            status_code=503,
        )

    return proxy


@core_app.middleware("http")
async def vercel_path_rewrite_middleware(request: Request, call_next):
    """
    Restores original requested path on Vercel Serverless deployments.
    When Vercel rewrites /api/(.*) or /health to the serverless function endpoint (/api),
    Vercel passes the original requested path in the 'x-matched-path' header.
    This middleware updates request.scope['path'] so FastAPI's router matches the exact route.
    """
    matched = request.headers.get("x-matched-path")
    if matched and request.scope.get("path") in ("/api", "/api/", "/api/index", "/api/index.py"):
        request.scope["path"] = matched.split("?")[0]
    return await call_next(request)


@core_app.get("/api")
@core_app.get("/api/")
def core_api_root():
    return {
        "status": "healthy",
        "service": "AgentShield API",
        "version": "0.2.0",
        "engine": "AgentShield Runtime",
        "read_only": False,
    }


if _is_staging_environment():
    app = create_staging_proxy_app()
else:
    app = core_app
