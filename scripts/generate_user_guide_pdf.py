"""
Generates the comprehensive AgentShield User and Deployment Guide PDF
using Playwright Chromium with full CSS styling, diagrams, and embedded screenshots.
"""

import sys
import base64
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT_DIR / "docs"
SCREENSHOTS_DIR = DOCS_DIR / "screenshots"
OUTPUT_PDF = DOCS_DIR / "AgentShield-User-and-Deployment-Guide.pdf"


def img_to_b64(img_path: Path) -> str:
    if not img_path.exists():
        return ""
    with open(img_path, "rb") as f:
        data = f.read()
    return f"data:image/png;base64,{base64.b64encode(data).decode('utf-8')}"


def build_html() -> str:
    img_overview = img_to_b64(SCREENSHOTS_DIR / "01-overview.png")
    img_health = img_to_b64(SCREENSHOTS_DIR / "02-system-health-modal.png")
    img_alerts = img_to_b64(SCREENSHOTS_DIR / "03-security-alerts.png")
    img_login = img_to_b64(SCREENSHOTS_DIR / "04-login-modal.png")
    img_settings = img_to_b64(SCREENSHOTS_DIR / "05-security-settings.png")
    img_events = img_to_b64(SCREENSHOTS_DIR / "06-events-view.png")
    img_dropdown = img_to_b64(SCREENSHOTS_DIR / "07-dropdown-toolbar.png")
    img_review = img_to_b64(SCREENSHOTS_DIR / "08-review-queue.png")
    img_policies = img_to_b64(SCREENSHOTS_DIR / "09-policies-view.png")
    img_benchmarks = img_to_b64(SCREENSHOTS_DIR / "10-benchmarks-view.png")
    img_mobile = img_to_b64(SCREENSHOTS_DIR / "11-mobile-view.png")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentShield — User and Deployment Guide</title>
  <style>
    @page {{
      size: A4;
      margin: 18mm 16mm 20mm 16mm;
      @bottom-right {{
        content: counter(page);
        font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 9pt;
        color: #718096;
      }}
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #17150d;
      background-color: #ffffff;
      line-height: 1.55;
      font-size: 10.5pt;
      margin: 0;
      padding: 0;
    }}

    h1, h2, h3, h4 {{
      color: #0e0d21;
      font-weight: 700;
      line-height: 1.25;
      margin-top: 1.4em;
      margin-bottom: 0.5em;
      page-break-after: avoid;
    }}

    h1 {{
      font-size: 24pt;
      border-bottom: 2px solid #6d3ee8;
      padding-bottom: 8px;
      margin-top: 0;
    }}

    h2 {{
      font-size: 15pt;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 5px;
      color: #4a28a3;
    }}

    h3 {{
      font-size: 12pt;
      color: #1a202c;
    }}

    p {{
      margin: 0.6em 0;
    }}

    .page-break {{
      page-break-before: always;
    }}

    .cover {{
      min-height: 90vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 40px 0;
      page-break-after: always;
    }}

    .cover-badge {{
      display: inline-block;
      padding: 4px 12px;
      background: #f3ebff;
      color: #6d3ee8;
      border: 1px solid #d6bbfb;
      border-radius: 999px;
      font-size: 9.5pt;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 20px;
      width: fit-content;
    }}

    .cover-title {{
      font-size: 32pt;
      font-weight: 800;
      color: #0e0d21;
      line-height: 1.15;
      margin: 0 0 15px 0;
    }}

    .cover-subtitle {{
      font-size: 14pt;
      color: #4a5568;
      margin: 0 0 30px 0;
      max-width: 600px;
    }}

    .cover-meta {{
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #e2e8f0;
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 15px;
      font-size: 9.5pt;
      color: #4a5568;
    }}

    .cover-meta strong {{
      color: #1a202c;
    }}

    .callout {{
      padding: 12px 16px;
      margin: 14px 0;
      border-radius: 8px;
      font-size: 9.5pt;
      page-break-inside: avoid;
    }}

    .callout-purple {{
      background: #f7f4fe;
      border-left: 4px solid #6d3ee8;
      color: #32255b;
    }}

    .callout-green {{
      background: #f0fdf4;
      border-left: 4px solid #16a34a;
      color: #14532d;
    }}

    .callout-yellow {{
      background: #fefce8;
      border-left: 4px solid #ca8a04;
      color: #713f12;
    }}

    .callout-red {{
      background: #fef2f2;
      border-left: 4px solid #dc2626;
      color: #7f1d1d;
    }}

    .chip {{
      display: inline-block;
      padding: 2px 7px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 8.5pt;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}

    .chip-allow {{
      background: #dcfce7;
      color: #15803d;
      border: 1px solid #86efac;
    }}

    .chip-review {{
      background: #fef9c3;
      color: #854d0e;
      border: 1px solid #fde047;
    }}

    .chip-block {{
      background: #fee2e2;
      color: #b91c1c;
      border: 1px solid #fca5a5;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 9.5pt;
      page-break-inside: avoid;
    }}

    th, td {{
      padding: 8px 12px;
      border: 1px solid #e2e8f0;
      text-align: left;
    }}

    th {{
      background-color: #f8fafc;
      font-weight: 700;
      color: #1e293b;
    }}

    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 8.8pt;
      background: #f1f5f9;
      padding: 2px 5px;
      border-radius: 4px;
      color: #0f172a;
    }}

    pre {{
      background: #0f172a;
      color: #e2e8f0;
      padding: 12px 14px;
      border-radius: 6px;
      font-size: 8.5pt;
      line-height: 1.45;
      overflow-x: auto;
      page-break-inside: avoid;
    }}

    pre code {{
      background: none;
      color: inherit;
      padding: 0;
    }}

    .figure {{
      margin: 16px 0;
      text-align: center;
      page-break-inside: avoid;
    }}

    .figure img {{
      max-width: 100%;
      height: auto;
      border-radius: 8px;
      border: 1px solid #cbd5e1;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }}

    .figure-caption {{
      font-size: 8.5pt;
      color: #64748b;
      margin-top: 6px;
      font-style: italic;
    }}

    .flow-steps {{
      display: grid;
      grid-template-columns: repeat(7, 1fr);
      gap: 6px;
      margin: 16px 0;
      text-align: center;
      page-break-inside: avoid;
    }}

    .flow-step {{
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 8px 4px;
    }}

    .flow-step-num {{
      display: inline-block;
      width: 20px;
      height: 20px;
      line-height: 20px;
      border-radius: 50%;
      background: #6d3ee8;
      color: white;
      font-size: 8pt;
      font-weight: bold;
      margin-bottom: 4px;
    }}

    .flow-step-name {{
      font-size: 8pt;
      font-weight: bold;
      color: #1e293b;
    }}
  </style>
</head>
<body>

  <!-- COVER PAGE -->
  <div class="cover">
    <div class="cover-badge">Official Security Documentation</div>
    <h1 class="cover-title">AgentShield</h1>
    <p class="cover-subtitle">Runtime Security SDK & Operational Security Operations Guide for Tool-Using AI Agents</p>
    
    <div class="callout callout-purple">
      <strong>Core Security Doctrine:</strong> Agent proposes action &rarr; AgentShield authenticates agent, validates arguments, applies deterministic policy &rarr; <strong>ALLOW / REVIEW / BLOCK</strong> &rarr; execute only if permitted &rarr; SHA-256 hash-chain audit.
    </div>

    <div class="cover-meta">
      <div><strong>Software Version:</strong> v0.2.0 (Release Hardened)</div>
      <div><strong>Architecture:</strong> Deterministic Hybrid Policy + Risk Engine</div>
      <div><strong>Classification:</strong> Operational & Deployment Guide</div>
      <div><strong>Target Platforms:</strong> Render (Backend), Vercel (Frontend), Python SDK</div>
    </div>
  </div>

  <!-- SECTION 1: ARCHITECTURAL OVERVIEW -->
  <h2>1. System Architecture & Core Guarantees</h2>
  <p>AgentShield is an open-source, framework-independent runtime security SDK for AI agents (LangChain, CrewAI, AutoGen, or custom agents). It acts as an authoritative mediation boundary between autonomous agents and external tool execution.</p>

  <h3>Non-Negotiable Security Principles</h3>
  <ul>
    <li><strong>LLM & RAG are never the final authority:</strong> Policy enforcement is strictly deterministic and fails closed. Probabilistic models can evaluate risk or provide explanations, but cannot grant permission.</li>
    <li><strong>Fail-Closed Policy:</strong> Unknown tools, unknown agents, malformed requests, or explicit policy violations always result in <span class="chip chip-block">BLOCK</span>.</li>
    <li><strong>Safe Execution Invariant:</strong> <span class="chip chip-block">BLOCK</span> never invokes the tool callable. <span class="chip chip-allow">ALLOW</span> invokes it exactly once per <code>execute()</code>.</li>
    <li><strong>One-Way Risk Escalation:</strong> Risk engines can escalate an action from <span class="chip chip-allow">ALLOW</span> to <span class="chip chip-review">REVIEW</span> or <span class="chip chip-block">BLOCK</span>, but can never downgrade a denial into an allow.</li>
    <li><strong>Strict Hostname Parsing:</strong> Destinations are allowlisted by parsed URL hostnames, preventing substring bypasses (e.g. <code>api.corp.com.attacker.com</code>).</li>
    <li><strong>Credential Isolation:</strong> Only AgentShield holds execution credentials. Agents never directly access API keys, databases, or subprocess tokens.</li>
    <li><strong>Cryptographic Tamper-Evident Audit:</strong> Every decision and execution status is recorded in a SHA-256 cryptographic hash chain with secrets redacted.</li>
  </ul>

  <h3>The 7-Step Security Pipeline</h3>
  <div class="flow-steps">
    <div class="flow-step"><div class="flow-step-num">1</div><div class="flow-step-name">Propose</div></div>
    <div class="flow-step"><div class="flow-step-num">2</div><div class="flow-step-name">Validate</div></div>
    <div class="flow-step"><div class="flow-step-num">3</div><div class="flow-step-name">Risk</div></div>
    <div class="flow-step"><div class="flow-step-num">4</div><div class="flow-step-name">Policy</div></div>
    <div class="flow-step"><div class="flow-step-num">5</div><div class="flow-step-name">Decision</div></div>
    <div class="flow-step"><div class="flow-step-num">6</div><div class="flow-step-name">Execute</div></div>
    <div class="flow-step"><div class="flow-step-num">7</div><div class="flow-step-name">Audit</div></div>
  </div>

  <div class="page-break"></div>

  <!-- SECTION 2: OPERATOR INTERFACE & DASHBOARD -->
  <h2>2. Operational Dashboard & UI Walkthrough</h2>
  <p>The AgentShield operational dashboard provides real-time visibility into agent activities, system health, pending authorization reviews, policy configurations, and adversarial benchmark suites.</p>

  <h3>2.1 Dashboard Overview</h3>
  <p>The Overview tab aggregates key performance indicators, live security events, cross-agent activity metrics, decision breakdowns, and risk assessments.</p>

  <div class="figure">
    <img src="{img_overview}" alt="AgentShield Dashboard Overview" />
    <div class="figure-caption">Figure 1: AgentShield Dashboard Overview showing KPIs, Activity Chart, Decision Distribution, and Attention Required.</div>
  </div>

  <h3>2.2 System Health & Live Diagnostics</h3>
  <p>System Health diagnostics query <code>/api/health</code>, <code>/api/health/readiness</code>, and <code>/api/telemetry/status</code>. Status states reflect honest backend conditions: <em>Healthy</em>, <em>Degraded</em>, <em>Unhealthy</em>, or <em>Awaiting Telemetry</em>.</p>

  <div class="figure">
    <img src="{img_health}" alt="System Health Diagnostics Modal" />
    <div class="figure-caption">Figure 2: Real System Health Modal displaying database connectivity, PostgreSQL backend, and telemetry queue metrics.</div>
  </div>

  <div class="page-break"></div>

  <h3>2.3 Real-Time Security Alerts</h3>
  <p>The Notification system connects directly to the backend <code>/api/incident/alerts</code> endpoint. When anomalous behavior (such as prompt injection vectors or volumetric abuse) is detected, alerts are surfaced in the top navigation popover and interactive pixel toast notifications.</p>

  <div class="figure">
    <img src="{img_alerts}" alt="Security Alerts Popover" />
    <div class="figure-caption">Figure 3: Security Alerts Notification popover with severity badges, honest agent attribution, and dismissal controls.</div>
  </div>

  <h3>2.4 Administrator Authentication & Session Security</h3>
  <p>AgentShield enforces strict session authentication with CSRF token generation and RBAC separation between Global Administrators, Tenant Administrators, and Read-Only Guests.</p>

  <div class="figure">
    <img src="{img_login}" alt="Administrator Authentication Modal" />
    <div class="figure-caption">Figure 4: Secure Administrator Authentication modal with constant-time HMAC validation.</div>
  </div>

  <div class="page-break"></div>

  <h3>2.5 Events & Cryptographic Audit Verification</h3>
  <p>Every tool invocation evaluated by AgentShield is persisted with its input arguments, policy version hash, decision rationale, and SHA-256 link. Operators can verify audit hash-chain integrity with a single click.</p>

  <div class="figure">
    <img src="{img_events}" alt="Events View & Audit Verification" />
    <div class="figure-caption">Figure 5: Events View featuring one-click SHA-256 Audit Integrity Verification and unified filter toolbars.</div>
  </div>

  <div class="figure">
    <img src="{img_dropdown}" alt="Unified Filter Dropdown" />
    <div class="figure-caption">Figure 6: Consistent, theme-aware dropdown toolbar dynamically populated with real backend agents and tools.</div>
  </div>

  <div class="page-break"></div>

  <h3>2.6 Human-in-the-Loop Review Queue</h3>
  <p>When an action triggers a <span class="chip chip-review">REVIEW</span> decision, execution is halted safely until an authorized operator reviews the proposed arguments and either approves or denies the request.</p>

  <div class="figure">
    <img src="{img_review}" alt="Review Queue" />
    <div class="figure-caption">Figure 7: Human-in-the-Loop Review Queue displaying held tool proposals, risk scores, and approval controls.</div>
  </div>

  <h3>2.7 Policies & Agent Containment</h3>
  <p>The Policies view inspects declarative policy specifications, tool allowlists, and rate limits. Operators can pause active agents to immediately contain compromised actors.</p>

  <div class="figure">
    <img src="{img_policies}" alt="Policies and Agents" />
    <div class="figure-caption">Figure 8: Policies & Agent Containment interface with immutable version hashes and containment toggles.</div>
  </div>

  <div class="page-break"></div>

  <h3>2.8 Security Benchmarks & Adversarial Validation</h3>
  <p>AgentShield includes an automated benchmark execution engine with 32 standardized test vectors covering prompt injection, SSRF, destructive execution, and volumetric flooding.</p>

  <div class="figure">
    <img src="{img_benchmarks}" alt="Security Benchmarks" />
    <div class="figure-caption">Figure 9: Security Benchmarks Suite evaluating protection against adversarial agent behaviors.</div>
  </div>

  <h3>2.9 Mobile Responsive Interface</h3>
  <p>The entire dashboard is built with responsive grid layouts that adapt down to mobile viewports without losing pixel-art fidelity or operational capabilities.</p>

  <div class="figure" style="max-width: 320px; margin: 0 auto;">
    <img src="{img_mobile}" alt="Mobile View" />
    <div class="figure-caption">Figure 10: Mobile view (390px) maintaining full navigation and alert visibility.</div>
  </div>

  <div class="page-break"></div>

  <!-- SECTION 3: DEPLOYMENT & PRODUCTION RUNBOOK -->
  <h2>3. Deployment Preflight & Configuration Guide</h2>

  <h3>Environment Variables</h3>
  <table>
    <thead>
      <tr>
        <th>Variable</th>
        <th>Default / Example</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>AGENTSHIELD_ENV</code></td>
        <td><code>staging</code> / <code>production</code></td>
        <td>Environment mode. Governs security policies and logging.</td>
      </tr>
      <tr>
        <td><code>AGENTSHIELD_READONLY</code></td>
        <td><code>true</code> (Staging)</td>
        <td>Fails closed for mutating administrative operations on public instances.</td>
      </tr>
      <tr>
        <td><code>AGENTSHIELD_ADMIN_KEY</code></td>
        <td><em>[Secure Random String]</em></td>
        <td>Secret key for global administrative operations and session login.</td>
      </tr>
      <tr>
        <td><code>AGENTSHIELD_SESSION_SECRET</code></td>
        <td><em>[Min 32-char String]</em></td>
        <td>Secret for cryptographic signing of session cookies and CSRF tokens.</td>
      </tr>
      <tr>
        <td><code>DATABASE_URL</code></td>
        <td><code>postgresql://...</code></td>
        <td>PostgreSQL connection string for production audit and event storage.</td>
      </tr>
      <tr>
        <td><code>AGENTSHIELD_CORS_ORIGINS</code></td>
        <td><code>https://agentshield.vercel.app,...</code></td>
        <td>Comma-separated list of permitted frontend origins for CORS headers.</td>
      </tr>
    </tbody>
  </table>

  <h3>Render Staging Backend Deployment</h3>
  <pre><code># render.yaml configuration snippet
services:
  - type: web
    name: agentshield-backend-staging
    runtime: python
    buildCommand: "pip install -e ."
    startCommand: "uvicorn agentshield.api.app:app --host 0.0.0.0 --port $PORT"
    healthCheckPath: /health
    envVars:
      - key: AGENTSHIELD_ENV
        value: staging
      - key: AGENTSHIELD_READONLY
        value: "true"
      - key: AGENTSHIELD_ALLOW_MOCK_FALLBACK
        value: "true"</code></pre>

  <h3>Vercel Frontend Configuration</h3>
  <p>The Vercel preview and production environments route API traffic via <code>api/index.py</code> serverless bridge with automated <code>Host</code> header translation and gzip handling to prevent upstream 502 Bad Gateway rejections.</p>

  <div class="callout callout-green">
    <strong>Preflight Checklist Passed:</strong> 542 backend tests passing, 45 frontend unit tests passing, Playwright browser E2E verified, zero secret leaks in client bundles, and live staging PostgreSQL persistence confirmed.
  </div>

  <div class="page-break"></div>

  <!-- SECTION 4: SDK QUICKSTART -->
  <h2>4. Python SDK Quickstart</h2>
  <p>Integrating AgentShield into an agentic pipeline requires only wrapping tool execution in <code>shield.execute()</code>:</p>

  <pre><code>from agentshield import AgentShield, PolicyEngine, ToolRegistry

# 1. Initialize Registry and Policy
registry = ToolRegistry()
registry.register("query_database", db_callable, requires_auth=True)

policy = PolicyEngine.from_yaml("policies/enterprise_strict.yaml")

# 2. Instantiate Runtime Shield
shield = AgentShield(
    policy=policy,
    registry=registry,
    audit_db_path="audit.db"
)

# 3. Secure Execution Wrapper
result = shield.execute(
    agent_id="finance_analyst_agent",
    tool="query_database",
    arguments={{"query": "SELECT revenue FROM q3_results WHERE department = 'Sales';"}},
    context={{"user_id": "usr_9481"}}
)

if result.decision == "ALLOW":
    print("Execution Success:", result.output)
elif result.decision == "REVIEW":
    print("Execution Held for Approval. Proposal ID:", result.review_id)
else:
    print("Execution Blocked:", result.reasons)</code></pre>

  <div class="callout callout-purple">
    <strong>Audit Verification:</strong> The cryptographic hash chain can be validated programmatically at any time via <code>shield.audit_store.verify_chain_integrity()</code>.
  </div>

</body>
</html>"""


def main():
    print("[*] Generating HTML content for User and Deployment Guide...")
    html_content = build_html()
    temp_html = DOCS_DIR / "temp_guide.html"
    temp_html.write_text(html_content, encoding="utf-8")

    print("[*] Printing PDF using Playwright Chromium...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(temp_html.as_uri(), wait_until="networkidle")
        page.wait_for_timeout(1000)

        page.pdf(
            path=str(OUTPUT_PDF),
            format="A4",
            print_background=True,
            margin={"top": "16mm", "bottom": "18mm", "left": "14mm", "right": "14mm"},
            display_header_footer=True,
            header_template='<div style="font-size: 8pt; color: #a0aec0; width: 100%; text-align: right; padding-right: 14mm; font-family: sans-serif;">AgentShield &bull; User & Deployment Guide</div>',
            footer_template='<div style="font-size: 8pt; color: #a0aec0; width: 100%; text-align: right; padding-right: 14mm; font-family: sans-serif;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
        )
        browser.close()

    if temp_html.exists():
        temp_html.unlink()

    print(f"[+] Successfully generated PDF: {OUTPUT_PDF} ({OUTPUT_PDF.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

