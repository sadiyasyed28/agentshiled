import React, { useState } from "react";
import { WindingPath } from "./components/WindingPath";
import type { PathStop } from "./components/WindingPath";
import {
  DEMO_STATS,
  DEMO_SECURITY_EVENTS,
  DEMO_POLICIES,
  DEMO_RISK_FACTORS,
} from "./mock/events";

const PIPELINE_STOPS: PathStop[] = [
  { id: 1, label: "Propose", description: "Agent Action", category: "proposal" },
  { id: 2, label: "Validate", description: "Schema & Format", category: "security" },
  { id: 3, label: "Risk", description: "Deterministic Score", category: "security" },
  { id: 4, label: "Policy", description: "Rules Engine", category: "security" },
  { id: 5, label: "Decision", description: "ALLOW / REVIEW / BLOCK", category: "security" },
  { id: 6, label: "Execute", description: "Callable Dispatch", category: "execution" },
  { id: 7, label: "Audit", description: "Telemetry Log", category: "audit" },
];

export const App: React.FC = () => {
  const [selectedStopIndex, setSelectedStopIndex] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<"all" | "BLOCK" | "REVIEW" | "ALLOW">("all");

  const filteredEvents = activeTab === "all"
    ? DEMO_SECURITY_EVENTS
    : DEMO_SECURITY_EVENTS.filter((e) => e.decision === activeTab);

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-200">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-[#0d111d]/90 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="h-9 w-9 rounded-lg bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-sky-500/20">
            AS
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight text-white">AgentShield</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-sky-400 font-mono border border-slate-700">
                SDK v0.1.0
              </span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium">
                [demo data]
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Deterministic runtime security & authorization layer for AI agents
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-slate-300 font-mono">Engine: FAIL-CLOSED</span>
          </div>
          <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800">
            <span className="text-slate-400">Authority:</span>
            <span className="text-sky-400 font-mono font-medium">Deterministic Policy</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Section 1: Interactive SVG Winding Path Pipeline */}
        <section className="bg-[#0f1422] border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h2 className="text-base font-semibold text-white tracking-wide">
                Runtime Pipeline Flow
              </h2>
              <p className="text-xs text-slate-400">
                7-stop deterministic execution sequence. Click any stage to inspect its role.
              </p>
            </div>
            <div className="text-xs text-slate-400 font-mono bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
              Active Focus: <span className="text-sky-400 font-bold">{PIPELINE_STOPS[selectedStopIndex].label}</span> (Stage {selectedStopIndex + 1}/7)
            </div>
          </div>

          {/* Reusable WindingPath SVG Component */}
          <WindingPath
            stops={PIPELINE_STOPS}
            activeStopIndex={selectedStopIndex}
            onSelectStop={(stop) => setSelectedStopIndex(stop.id - 1)}
          />

          {/* Stage detail box */}
          <div className="mt-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-start justify-between">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-sky-400 font-semibold">
                Stage {PIPELINE_STOPS[selectedStopIndex].id}: {PIPELINE_STOPS[selectedStopIndex].label}
              </span>
              <p className="text-sm text-slate-300 mt-1">
                {selectedStopIndex === 0 && "Agent proposes an action with designated tool and input arguments. No execution occurs at this point."}
                {selectedStopIndex === 1 && "Action validated against dataclass schema. Malformed actions, missing fields, or invalid types fail immediately as BLOCK."}
                {selectedStopIndex === 2 && "Standalone deterministic RiskEngine calculates risk score (0-100) and extracts deduplicated factors without LLM dependency."}
                {selectedStopIndex === 3 && "PolicyEngine checks configured agent permissions, tool whitelists, argument caps, and explicit denials."}
                {selectedStopIndex === 4 && "Deterministic authorization verdict: ALLOW, REVIEW, or BLOCK. Risk score cannot override an explicit policy rejection."}
                {selectedStopIndex === 5 && "Tool callable is invoked if and only if decision is ALLOW. BLOCK guarantees 0 callable invocations; ALLOW invokes exactly once."}
                {selectedStopIndex === 6 && "Decision and execution outcomes logged into separate audit streams. Secrets and credentials strictly scrubbed."}
              </p>
            </div>
            <div className="flex gap-2 shrink-0 ml-4">
              <button
                onClick={() => setSelectedStopIndex((prev) => Math.max(0, prev - 1))}
                disabled={selectedStopIndex === 0}
                className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed text-slate-300"
              >
                Prev
              </button>
              <button
                onClick={() => setSelectedStopIndex((prev) => Math.min(PIPELINE_STOPS.length - 1, prev + 1))}
                disabled={selectedStopIndex === PIPELINE_STOPS.length - 1}
                className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-30 disabled:cursor-not-allowed text-slate-300"
              >
                Next
              </button>
            </div>
          </div>
        </section>

        {/* Section 2: Overview Decision Counts */}
        <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-[#0f1422] border border-slate-800 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-mono">
              <span>Total Evaluated</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">demo</span>
            </div>
            <div className="text-3xl font-bold font-mono text-white mt-2">
              {DEMO_STATS.totalEvaluated}
            </div>
            <div className="text-xs text-slate-500 mt-1">Actions inspected by AgentShield</div>
          </div>

          <div className="bg-[#0f1422] border border-emerald-900/30 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between text-xs text-emerald-400 uppercase font-mono">
              <span>ALLOW Decisions</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300">demo</span>
            </div>
            <div className="text-3xl font-bold font-mono text-emerald-400 mt-2">
              {DEMO_STATS.allowCount}
            </div>
            <div className="text-xs text-slate-500 mt-1">Callable invoked exactly once</div>
          </div>

          <div className="bg-[#0f1422] border border-amber-900/30 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between text-xs text-amber-400 uppercase font-mono">
              <span>REVIEW Decisions</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300">demo</span>
            </div>
            <div className="text-3xl font-bold font-mono text-amber-400 mt-2">
              {DEMO_STATS.reviewCount}
            </div>
            <div className="text-xs text-slate-500 mt-1">Awaiting human sign-off</div>
          </div>

          <div className="bg-[#0f1422] border border-rose-900/30 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between text-xs text-rose-400 uppercase font-mono">
              <span>BLOCK Decisions</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300">demo</span>
            </div>
            <div className="text-3xl font-bold font-mono text-rose-400 mt-2">
              {DEMO_STATS.blockCount}
            </div>
            <div className="text-xs text-slate-500 mt-1">Callable strictly prevented (0 calls)</div>
          </div>
        </section>

        {/* Section 3: Main Two-Column Layout (Security Events + Side Blocks) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left 2 Cols: Security Events Log */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-[#0f1422] border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
                <div>
                  <h3 className="text-base font-semibold text-white">Security Events</h3>
                  <p className="text-xs text-slate-400">
                    Authorization verdicts with separate execution tracking.
                  </p>
                </div>

                {/* Filter buttons */}
                <div className="flex gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800 self-start">
                  {(["all", "BLOCK", "REVIEW", "ALLOW"] as const).map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`text-xs px-2.5 py-1 rounded font-medium transition-all ${
                        activeTab === tab
                          ? "bg-slate-800 text-white shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>
              </div>

              {/* Event rows */}
              <div className="divide-y divide-slate-800/60 mt-2">
                {filteredEvents.map((evt) => (
                  <div key={evt.id} className="py-4 hover:bg-slate-900/40 px-2 rounded-lg transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2.5">
                        <span
                          className={`text-xs px-2 py-0.5 rounded font-mono font-bold ${
                            evt.decision === "ALLOW"
                              ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/50"
                              : evt.decision === "REVIEW"
                              ? "bg-amber-950/80 text-amber-400 border border-amber-800/50"
                              : "bg-rose-950/80 text-rose-400 border border-rose-800/50"
                          }`}
                        >
                          {evt.decision}
                        </span>
                        <span className="font-mono text-xs text-sky-400 font-semibold">{evt.agent}</span>
                        <span className="text-xs text-slate-500">→</span>
                        <span className="font-mono text-xs text-slate-200 font-medium">{evt.tool}()</span>
                      </div>

                      <div className="flex items-center space-x-3 text-xs">
                        <span className="font-mono text-slate-400">{evt.timestamp}</span>
                        <span
                          className={`text-[11px] px-2 py-0.5 rounded font-mono ${
                            evt.executionStatus === "executed"
                              ? "bg-emerald-950/50 text-emerald-400 border border-emerald-900/30"
                              : "bg-slate-800/60 text-slate-400 border border-slate-700/40"
                          }`}
                        >
                          {evt.executionStatus}
                        </span>
                      </div>
                    </div>

                    <div className="mt-2 text-xs text-slate-400 font-mono bg-slate-950/60 p-2 rounded border border-slate-900">
                      args: {JSON.stringify(evt.arguments)}
                    </div>

                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {evt.reasons.map((r, i) => (
                        <span
                          key={i}
                          className="text-[11px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Col: Policies, Risk, Attack Simulator, Benchmarks */}
          <div className="space-y-6">
            {/* Policies Block */}
            <div className="bg-[#0f1422] border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-base font-semibold text-white">Policies</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800/40">
                  PolicyEngine active
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Deterministic security rules configured in PolicyConfiguration.
              </p>
              <div className="space-y-3 mt-4">
                {DEMO_POLICIES.map((p, idx) => (
                  <div key={idx} className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-slate-200">{p.name}</span>
                      <span className="font-mono text-[10px] text-emerald-400 uppercase">{p.status}</span>
                    </div>
                    <div className="text-slate-400 mt-1 font-mono text-[11px]">Scope: {p.target}</div>
                    <p className="text-slate-400 mt-1">{p.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Risk Factors Block */}
            <div className="bg-[#0f1422] border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-base font-semibold text-white">Risk</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/40">
                  RiskEngine (0-100)
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Deduplicated factors with centralized severity thresholds.
              </p>
              <div className="space-y-2 mt-4">
                {DEMO_RISK_FACTORS.map((rf) => (
                  <div key={rf.id} className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="font-mono font-medium text-purple-300">{rf.name}</span>
                      <span className="font-mono text-slate-400 text-[11px]">wt: +{rf.weight}</span>
                    </div>
                    <p className="text-slate-400 mt-1 text-[11px]">{rf.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Attack Simulator Block (Live/Empty State) */}
            <div className="bg-[#0f1422] border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-base font-semibold text-white">Attack Simulator</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                  [live]
                </span>
              </div>
              <div className="mt-4 p-6 rounded-xl bg-slate-900/40 border border-dashed border-slate-800 text-center">
                <div className="text-slate-500 text-xs font-mono">No active simulation running</div>
                <p className="text-xs text-slate-400 mt-1">
                  Connect FastAPI simulator endpoint to trigger synthetic red-team payloads against AgentShield.
                </p>
                <button
                  disabled
                  className="mt-3 px-3 py-1.5 rounded bg-slate-800/60 text-slate-500 text-xs font-medium cursor-not-allowed border border-slate-700/40"
                >
                  Start Simulation
                </button>
              </div>
            </div>

            {/* Benchmarks Block (Empty State) */}
            <div className="bg-[#0f1422] border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-base font-semibold text-white">Benchmarks</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                  [live]
                </span>
              </div>
              <div className="mt-4 p-6 rounded-xl bg-slate-900/40 border border-dashed border-slate-800 text-center">
                <div className="text-slate-500 text-xs font-mono">No benchmark runs recorded</div>
                <p className="text-xs text-slate-400 mt-1">
                  Latency, overhead & policy evaluation timings will appear here once connected to benchmark suite.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;
