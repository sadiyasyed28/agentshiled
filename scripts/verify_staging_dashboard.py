import asyncio
import os
import subprocess
import sys
import time
import urllib.request
from playwright.async_api import async_playwright

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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

def kill_proc(proc: subprocess.Popen):
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            proc.terminate()
    except Exception:
        pass

async def test_staging_dashboard():
    print("--- Starting Vite with Staging Backend Configuration ---")
    env = os.environ.copy()
    env["VITE_BACKEND_TARGET"] = "https://agentshield-backend-staging.onrender.com"
    
    frontend_proc = subprocess.Popen(
        ["npx", "vite", "--port", "5174"],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=True,
    )
    
    if not wait_for_http("http://localhost:5174", timeout=20.0):
        kill_proc(frontend_proc)
        print("Failed to start Vite on port 5174")
        return False

    success = False
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(viewport={"width": 1440, "height": 900})
            page = await context.new_page()

            console_logs = []
            network_calls = []

            page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
            page.on("response", lambda resp: network_calls.append(f"{resp.request.method} {resp.url} -> {resp.status}"))

            print("Navigating to Staging Dashboard at http://localhost:5174...")
            await page.goto("http://localhost:5174", wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(3000)

            # Check for title
            title = await page.title()
            print(f"Title: {title}")

            # Check Health status text
            content = await page.content()
            has_disconnected = "API DISCONNECTED" in content
            print(f"'API DISCONNECTED' in DOM: {has_disconnected}")

            # Check Header text
            health_el = page.locator("header").first
            header_text = await health_el.inner_text()
            print(f"Header text:\n{header_text}")

            # Navigate to Events view
            events_nav = page.locator("button:has-text('Events')").first
            await events_nav.click()
            await page.wait_for_timeout(2000)

            events_content = await page.content()
            has_events_disconnected = "API DISCONNECTED" in events_content
            print(f"Events tab 'API DISCONNECTED': {has_events_disconnected}")

            # Look for live telemetry chip or events table
            chip_text = ""
            try:
                chip = page.locator("span:has-text('LIVE TELEMETRY')").first
                if await chip.is_visible():
                    chip_text = await chip.inner_text()
            except Exception:
                pass
            print(f"Events chip: {chip_text}")

            print("\n--- Network API Calls ---")
            for call in network_calls:
                if "/api" in call or "/events" in call or "/health" in call:
                    print(call)

            assert not has_disconnected, "Dashboard should not show API DISCONNECTED"
            assert not has_events_disconnected, "Events view should not show API DISCONNECTED"
            assert "Healthy" in header_text or "Awaiting telemetry" in header_text, "Health indicator should resolve"
            print("\n>>> LIVE STAGING VERIFICATION PASSED! <<<")
            success = True

            await browser.close()
    finally:
        kill_proc(frontend_proc)

    return success

if __name__ == "__main__":
    result = asyncio.run(test_staging_dashboard())
    sys.exit(0 if result else 1)
