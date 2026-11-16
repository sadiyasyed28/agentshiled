import type { ApiSimulationRun } from '../../api/client';
import type { BenchmarkRunRecord } from './benchmarkTypes';

export const EMPTY_BENCHMARK_RUN: BenchmarkRunRecord = {
  id: 'none',
  dataset: 'No Live Simulation Recorded',
  policyVersion: 'Runtime Active Policy',
  total: 0,
  blocked: 0,
  fp: 0,
  bypasses: 0,
  status: 'Completed',
  timestamp: 'Never',
  benignCases: 0,
  maliciousCases: 0,
  unauthorizedExecutionsBaseline: 0,
  unauthorizedExecutionsProtected: 0,
  blockedMaliciousBaseline: 0,
  blockedMaliciousProtected: 0,
  fpBaseline: 0,
  fpProtected: 0,
  benignAllowedBaseline: 0,
  benignAllowedProtected: 0,
  allowedCount: 0,
  allowedPercent: 0,
  reviewCount: 0,
  reviewPercent: 0,
  blockedCount: 0,
  blockedPercent: 0,
  categoryResults: [],
};

/**
 * Maps flat simulation run items from the backend (/api/simulator/history)
 * into structured BenchmarkRunRecord objects grouped by execution batch.
 */
export function mapSimulationHistoryToRuns(history: ApiSimulationRun[]): BenchmarkRunRecord[] {
  if (!history || history.length === 0) {
    return [];
  }

  // Sort descending by timestamp
  const sorted = [...history].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

  // Group by time window (runs within 120 seconds belong to same benchmark suite run)
  const batches: ApiSimulationRun[][] = [];
  let currentBatch: ApiSimulationRun[] = [];
  let lastTimestamp = 0;

  for (const item of sorted) {
    const itemTime = item.timestamp || 0;
    if (currentBatch.length === 0) {
      currentBatch.push(item);
      lastTimestamp = itemTime;
    } else if (Math.abs(lastTimestamp - itemTime) <= 120) {
      currentBatch.push(item);
      lastTimestamp = itemTime;
    } else {
      batches.push(currentBatch);
      currentBatch = [item];
      lastTimestamp = itemTime;
    }
  }
  if (currentBatch.length > 0) {
    batches.push(currentBatch);
  }

  return batches.map((batchRuns, idx) => {
    const first = batchRuns[0];
    const total = batchRuns.length;
    const blockedCount = batchRuns.filter((r) => r.actual_decision === 'BLOCK').length;
    const allowedCount = batchRuns.filter((r) => r.actual_decision === 'ALLOW').length;
    const reviewCount = batchRuns.filter((r) => r.actual_decision === 'REVIEW').length;
    const benignCount = batchRuns.filter((r) => r.expected_decision === 'ALLOW').length;
    const maliciousCount = batchRuns.filter((r) => r.expected_decision !== 'ALLOW').length;

    // False positives: expected ALLOW but received BLOCK
    const fpCount = batchRuns.filter(
      (r) => r.expected_decision === 'ALLOW' && r.actual_decision === 'BLOCK'
    ).length;

    // Bypasses: expected BLOCK but received ALLOW
    const bypassCount = batchRuns.filter(
      (r) => r.expected_decision === 'BLOCK' && r.actual_decision === 'ALLOW'
    ).length;

    // Category aggregation
    const catMap = new Map<string, { total: number; pass: number }>();
    batchRuns.forEach((r) => {
      const cat = r.attack_category || 'General';
      const cur = catMap.get(cat) || { total: 0, pass: 0 };
      cur.total += 1;
      if (r.expectation_matched) cur.pass += 1;
      catMap.set(cat, cur);
    });

    const categoryResults = Array.from(catMap.entries()).map(([category, stats]) => ({
      category,
      completed: stats.pass,
      total: stats.total,
      ratio: `${stats.pass}/${stats.total}`,
      passRate: stats.total > 0 ? Math.round((stats.pass / stats.total) * 100) : 0,
      description: `Live simulated attack runs under category ${category}`,
    }));

    const rawMs = first.timestamp ? (first.timestamp > 1e11 ? first.timestamp : first.timestamp * 1000) : Date.now();
    const dateObj = new Date(rawMs);
    const dateStr = dateObj.toISOString().slice(0, 10).replace(/-/g, '_');
    const runId = `sim_run_${dateStr}_${String(idx + 1).padStart(2, '0')}`;

    return {
      id: runId,
      dataset: `Live Simulation (${total} scenarios)`,
      policyVersion: 'Runtime Active Policy',
      total,
      blocked: blockedCount,
      fp: fpCount,
      bypasses: bypassCount,
      status: 'Completed',
      timestamp: dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' }),
      benignCases: benignCount,
      maliciousCases: maliciousCount,
      unauthorizedExecutionsBaseline: maliciousCount,
      unauthorizedExecutionsProtected: bypassCount,
      blockedMaliciousBaseline: 0,
      blockedMaliciousProtected: blockedCount,
      fpBaseline: 0,
      fpProtected: fpCount,
      benignAllowedBaseline: benignCount,
      benignAllowedProtected: allowedCount,
      allowedCount,
      allowedPercent: total > 0 ? Number(((allowedCount / total) * 100).toFixed(1)) : 0,
      reviewCount,
      reviewPercent: total > 0 ? Number(((reviewCount / total) * 100).toFixed(1)) : 0,
      blockedCount,
      blockedPercent: total > 0 ? Number(((blockedCount / total) * 100).toFixed(1)) : 0,
      categoryResults,
    };
  });
}
