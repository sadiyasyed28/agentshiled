import asyncio
import sys
from playwright.async_api import async_playwright

async def verify_live_production():
    url = "https://agentshiled.vercel.app"
    print(f"Navigating to {url}...")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        console_logs = []
        network_logs = []

        page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
        page.on("response", lambda resp: network_logs.append(f"{resp.request.method} {resp.url} -> {resp.status}"))

        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)
            print(f"Page response status: {resp.status}")
        except Exception as e:
            print(f"Page goto failed/timed out: {e}")

        await page.wait_for_timeout(3000)

        # Check for key UI elements
        title = await page.title()
        print(f"Page title: {title}")

        content = await page.content()
        has_unable = "Unable to connect" in content or "unable to connect" in content.lower()
        print(f"'Unable to connect' in DOM: {has_unable}")

        # Check for Health indicator
        health_text = ""
        try:
            health_el = page.locator("text=Healthy").first
            if await health_el.is_visible():
                health_text = "Found 'Healthy' badge"
        except Exception:
            pass

        print(f"Health indicator: {health_text}")

        # Print relevant network requests
        api_requests = [n for n in network_logs if "/api" in n or "/health" in n]
        print("\n--- Live API Network Requests ---")
        for req in api_requests:
            print(req)

        print("\n--- Console Logs ---")
        for log in console_logs[-15:]:
            print(log)

        await browser.close()

if __name__ == "__main__":
    asyncio.run(verify_live_production())
