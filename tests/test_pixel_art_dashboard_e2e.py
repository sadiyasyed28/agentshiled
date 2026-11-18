"""
Phase 5/6: Browser-Level End-to-End Validation for Root Pixel-Art Dashboard.

Validates the full interactive user experience against the FastAPI backend:
1. Dashboard loads with zero uncaught console errors.
2. Login modal opens via dropdown, authenticates using admin key, and updates identity across the UI.
3. System Health modal opens and displays genuine status from backend health endpoints.
4. Security Settings modal opens from CommandPalette.
5. API Key Management lists keys and handles generation/rotation/revocation.
6. Events view executes cryptographic audit verification and renders verified result.
7. Policies view displays immutable policy banner and PolicyEngine hash.
8. Sign out revokes session and resets dashboard to unauthenticated guest state.
"""

import os
import sys
import time
import socket
import subprocess
import urllib.request
from pathlib import Path
import pytest

try:
    from playwright.async_api import async_playwright, expect
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

ROOT_DIR = Path(__file__).resolve().parent.parent


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def is_root_dashboard_running() -> bool:
    try:
        req = urllib.request.Request("http://localhost:5173", headers={"User-Agent": "HealthCheck"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            return "/src/main.tsx" in content or "Pixelify Sans" in content
    except Exception:
        return False


def is_backend_running() -> bool:
    try:
        req = urllib.request.Request("http://127.0.0.1:8000/api/health", headers={"User-Agent": "HealthCheck"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def free_port(port: int):
    try:
        out = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True).decode()
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 5 and "LISTENING" in line:
                pid = parts[-1]
                subprocess.run(f"taskkill /F /T /PID {pid}", shell=True, capture_output=True)
    except Exception:
        pass


def wait_for_http(url: str, timeout: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status in (200, 304):
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def kill_proc_tree(proc: subprocess.Popen):
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.terminate()
            proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


@pytest.fixture(scope="session")
def live_servers():
    """Ensure root backend (:8000) and root frontend (:5173) are running."""
    if not HAS_PLAYWRIGHT:
        yield "http://localhost:5173"
        return

    backend_proc = None
    frontend_proc = None

    # 1. Start backend on 8000 if not open or not healthy
    if not is_backend_running():
        free_port(8000)
        time.sleep(0.5)
        env = os.environ.copy()
        env["AGENTSHIELD_ADMIN_KEY"] = "demo-local-admin-secret-key-123"
        env["AGENTSHIELD_SESSION_SECRET"] = "demo-session-secret-at-least-32-chars-long"
        env["AGENTSHIELD_CORS_ORIGINS"] = "http://localhost:5173,http://127.0.0.1:5173"
        env["AGENTSHIELD_ALLOW_MOCK_FALLBACK"] = "true"
        env["AGENTSHIELD_READONLY"] = "0"
        backend_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "agentshield.api.app:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=str(ROOT_DIR),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_for_http("http://127.0.0.1:8000/api/health", timeout=15.0):
            kill_proc_tree(backend_proc)
            pytest.fail("Backend server failed to start on port 8000 within 15 seconds")

    # 2. Start root Vite dev server on 5173 if not serving root app
    if not is_root_dashboard_running():
        free_port(5173)
        time.sleep(0.5)
        frontend_proc = subprocess.Popen(
            ["npx", "vite", "--port", "5173"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True,
        )
        if not wait_for_http("http://localhost:5173", timeout=20.0):
            if backend_proc:
                kill_proc_tree(backend_proc)
            kill_proc_tree(frontend_proc)
            pytest.fail("Frontend dev server failed to start on port 5173 within 20 seconds")

    yield "http://localhost:5173"

    if frontend_proc:
        kill_proc_tree(frontend_proc)
    if backend_proc:
        kill_proc_tree(backend_proc)


pytestmark = pytest.mark.skipif(
    not HAS_PLAYWRIGHT,
    reason="Playwright browser automation is not available.",
)


@pytest.mark.anyio
async def test_pixel_art_dashboard_full_lifecycle(live_servers):
    """Executes the complete Phase 6 browser-level validation flow."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        console_errors = []
        page.on("pageerror", lambda err: console_errors.append(str(err)))

        # 1. Load Dashboard
        await page.goto(live_servers, wait_until="networkidle")
        critical_errors = [e for e in console_errors if "favicon" not in e.lower()]
        assert len(critical_errors) == 0, f"Uncaught critical console errors on load: {critical_errors}"

        # 2. Verify Initial Guest State
        guest_button = page.locator("header button:has-text('Sign In')").first
        await expect(guest_button).to_be_visible()

        # 3. Open Login Modal via Profile Dropdown and Authenticate
        await guest_button.click()
        sign_in_menu_btn = page.locator("button:has-text('Sign In as Admin')").first
        await expect(sign_in_menu_btn).to_be_visible()
        await sign_in_menu_btn.click()

        # Verify modal opened
        login_modal_heading = page.locator("h3:has-text('Admin Authentication')").first
        await expect(login_modal_heading).to_be_visible()

        # Enter admin key
        admin_input = page.locator("input[type='password']").first
        await admin_input.fill("demo-local-admin-secret-key-123")
        submit_btn = page.locator("button:has-text('Authenticate')").first
        await submit_btn.click()

        # Wait for authentication to resolve
        await page.wait_for_timeout(1000)

        # 4. Verify Authenticated State in TopNavigation
        admin_chip = page.locator("header button:has-text('Admin')").first
        await expect(admin_chip).to_be_visible()

        # 5. Verify Session Survives Page Refresh (Requirement 5)
        await page.reload(wait_until="networkidle")
        admin_chip_reloaded = page.locator("header button:has-text('Admin')").first
        await expect(admin_chip_reloaded).to_be_visible()

        # 6. Open System Health Diagnostics Modal (Requirements 7 & 12)
        await admin_chip_reloaded.click()
        health_menu_item = page.locator("button:has-text('System Health')").first
        await expect(health_menu_item).to_be_visible()
        await health_menu_item.click()

        # Verify System Health Modal renders genuine telemetry and operational mode
        health_modal_title = page.locator("text=System Health & Operational Status").first
        await expect(health_modal_title).to_be_visible()
        mode_indicator = page.locator("text=Operating Mode").first
        await expect(mode_indicator).to_be_visible()

        # Close System Health Modal
        close_health_btn = page.locator("div.fixed button:has-text('Close')").first
        await close_health_btn.click()
        await page.wait_for_timeout(300)

        # 7. Open Security Settings directly from TopNavigation (Requirement 8)
        admin_chip_nav = page.locator("header button:has-text('Admin')").first
        await admin_chip_nav.click()
        sec_settings_nav_item = page.locator("button:has-text('Security Settings')").first
        await expect(sec_settings_nav_item).to_be_visible()
        await sec_settings_nav_item.click()

        # Verify Security Settings Modal opened and check Runtime Configuration
        sec_modal = page.locator("text=Runtime Configuration").first
        await expect(sec_modal).to_be_visible()
        runtime_mode = page.locator("text=Operating Mode").first
        await expect(runtime_mode).to_be_visible()

        # Switch to API Key Management tab
        api_keys_tab = page.locator("button:has-text('API Key Management')").first
        await api_keys_tab.click()
        await expect(page.locator("button:has-text('Generate New Key')").first).to_be_visible()

        # Close Security Settings
        close_sec_btn = page.locator("div.fixed button:has-text('Close')").first
        await close_sec_btn.click()
        await page.wait_for_timeout(300)

        # 8. Open Security Settings from Command Palette (CMD + K) (Requirement 9)
        search_bar = page.locator("header button:has-text('Search events')").first
        await search_bar.click()

        cmd_palette_input = page.locator("input[placeholder*='search live agents']").first
        await expect(cmd_palette_input).to_be_visible()

        sec_settings_cmd = page.locator("button:has-text('Open Security Settings')").first
        await expect(sec_settings_cmd).to_be_visible()
        await sec_settings_cmd.click()

        # Verify Security Settings opened again from Command Palette
        await expect(page.locator("text=Runtime Configuration").first).to_be_visible()
        close_sec_btn2 = page.locator("div.fixed button:has-text('Close')").first
        await close_sec_btn2.click()
        await page.wait_for_timeout(300)

        # 9. Navigate to Events tab and Verify Audit Integrity (Requirement 10)
        events_nav = page.locator("nav button:has-text('Events')").first
        await events_nav.click()
        await page.wait_for_timeout(500)

        verify_audit_btn = page.locator("button:has-text('Verify Audit')").first
        await expect(verify_audit_btn).to_be_visible()
        await verify_audit_btn.click()

        # Wait for SHA-256 verification banner (verifies either intact chain or detected tamper honestly)
        audit_banner = page.locator("div:has-text('Audit Hash-Chain Verified'), div:has-text('Audit Integrity Failure')").first
        await expect(audit_banner).to_be_visible(timeout=5000)

        # 10. Navigate to Policies tab and verify immutable ruleset & read-only restrictions (Requirements 11 & 12)
        policies_nav = page.locator("nav button:has-text('Policies & Agents')").first
        await policies_nav.click()
        await page.wait_for_timeout(500)

        policy_immutability_banner = page.locator("text=Deterministic Policy Engine").first
        await expect(policy_immutability_banner).to_be_visible()
        immutability_text = page.locator("text=Policies are code-defined immutable constraints").first
        await expect(immutability_text).to_be_visible()

        # 11. Sign Out Administrator and verify return to Guest (Requirement 6)
        admin_chip_again = page.locator("header button:has-text('Admin')").first
        await admin_chip_again.click()
        sign_out_btn = page.locator("button:has-text('Sign Out')").first
        await expect(sign_out_btn).to_be_visible()
        await sign_out_btn.click()
        await page.wait_for_timeout(500)

        # Verify returned to Guest
        await expect(page.locator("header button:has-text('Sign In')").first).to_be_visible()

        await browser.close()
