"""
Script to capture crisp, high-resolution screenshots of all AgentShield views and modals
for documentation, deployment guides, and README showcases.
"""

import os
import sys
import time
import socket
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

ROOT_DIR = Path(__file__).resolve().parent.parent
SCREENSHOTS_DIR = ROOT_DIR / "docs" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
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


def kill_proc(proc):
    if not proc:
        return
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


def main():
    backend_proc = None
    frontend_proc = None

    try:
        print("[*] Checking / starting backend on port 8000...")
        if not is_port_open(8000):
            free_port(8000)
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
            time.sleep(3)

        print("[*] Checking / starting frontend on port 5173...")
        if not is_port_open(5173):
            free_port(5173)
            frontend_proc = subprocess.Popen(
                ["npx", "vite", "--port", "5173"],
                cwd=str(ROOT_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
            time.sleep(3)

        print("[*] Launching Playwright Chromium...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # Desktop Context (1440x900 @ 2x retina)
            context = browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
            page = context.new_page()

            # 1. Overview
            print("[*] Capturing 01-overview.png...")
            page.goto("http://localhost:5173?tab=overview", wait_until="networkidle")
            page.wait_for_timeout(1000)
            page.screenshot(path=str(SCREENSHOTS_DIR / "01-overview.png"))

            # 2. System Health Modal
            print("[*] Capturing 02-system-health-modal.png...")
            health_pill = page.locator("header button:has-text('Health:')").first
            if health_pill.is_visible():
                health_pill.click()
                page.wait_for_timeout(600)
                page.screenshot(path=str(SCREENSHOTS_DIR / "02-system-health-modal.png"))

            # 3. Notification Popup (Reload to close modal)
            print("[*] Capturing 03-security-alerts.png...")
            page.goto("http://localhost:5173?tab=overview", wait_until="networkidle")
            page.wait_for_timeout(600)
            bell_btn = page.locator("header button[title*='Security Alerts']").first
            if bell_btn.is_visible():
                bell_btn.click()
                page.wait_for_timeout(500)
                page.screenshot(path=str(SCREENSHOTS_DIR / "03-security-alerts.png"))

            # 4. Sign-In Modal
            print("[*] Capturing 04-login-modal.png...")
            page.goto("http://localhost:5173?tab=overview", wait_until="networkidle")
            page.wait_for_timeout(600)
            sign_in_btn = page.locator("header button:has-text('Sign In')").first
            if sign_in_btn.is_visible():
                sign_in_btn.click()
                page.wait_for_timeout(300)
                admin_menu_item = page.locator("button:has-text('Sign In as Admin')").first
                if admin_menu_item.is_visible():
                    admin_menu_item.click()
                    page.wait_for_timeout(500)
                    page.screenshot(path=str(SCREENSHOTS_DIR / "04-login-modal.png"))
                    # Authenticate
                    page.locator("input[type='password']").fill("demo-local-admin-secret-key-123")
                    page.locator("button:has-text('Authenticate')").click()
                    page.wait_for_timeout(1000)

            # 5. Security Settings Modal
            print("[*] Capturing 05-security-settings.png...")
            profile_btn = page.locator("header button:has-text('Admin')").first
            if profile_btn.is_visible():
                profile_btn.click()
                page.wait_for_timeout(300)
                sec_btn = page.locator("button:has-text('Security Settings')").first
                if sec_btn.is_visible():
                    sec_btn.click()
                    page.wait_for_timeout(600)
                    page.screenshot(path=str(SCREENSHOTS_DIR / "05-security-settings.png"))

            # 6. Events View
            print("[*] Capturing 06-events-view.png...")
            page.goto("http://localhost:5173?tab=events", wait_until="networkidle")
            page.wait_for_timeout(800)
            page.screenshot(path=str(SCREENSHOTS_DIR / "06-events-view.png"))

            # 7. Unified Dropdown Toolbar
            print("[*] Capturing 07-dropdown-toolbar.png...")
            decision_btn = page.locator("button:has-text('Decision')").first
            if decision_btn.is_visible():
                decision_btn.click()
                page.wait_for_timeout(400)
                page.screenshot(path=str(SCREENSHOTS_DIR / "07-dropdown-toolbar.png"))

            # 8. Review Queue View
            print("[*] Capturing 08-review-queue.png...")
            page.goto("http://localhost:5173?tab=review", wait_until="networkidle")
            page.wait_for_timeout(800)
            page.screenshot(path=str(SCREENSHOTS_DIR / "08-review-queue.png"))

            # 9. Policies & Agents View
            print("[*] Capturing 09-policies-view.png...")
            page.goto("http://localhost:5173?tab=policies", wait_until="networkidle")
            page.wait_for_timeout(800)
            page.screenshot(path=str(SCREENSHOTS_DIR / "09-policies-view.png"))

            # 10. Benchmarks View
            print("[*] Capturing 10-benchmarks-view.png...")
            page.goto("http://localhost:5173?tab=benchmarks", wait_until="networkidle")
            page.wait_for_timeout(800)
            page.screenshot(path=str(SCREENSHOTS_DIR / "10-benchmarks-view.png"))

            # 11. Mobile Responsive View (390x844)
            print("[*] Capturing 11-mobile-view.png...")
            mobile_context = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
            mobile_page = mobile_context.new_page()
            mobile_page.goto("http://localhost:5173?tab=overview", wait_until="networkidle")
            mobile_page.wait_for_timeout(800)
            mobile_page.screenshot(path=str(SCREENSHOTS_DIR / "11-mobile-view.png"))

            browser.close()
            print("[+] All 11 screenshots captured successfully!")

    finally:
        if frontend_proc:
            print("[*] Cleaning up frontend dev server...")
            kill_proc(frontend_proc)
        if backend_proc:
            print("[*] Cleaning up backend server...")
            kill_proc(backend_proc)


if __name__ == "__main__":
    main()
