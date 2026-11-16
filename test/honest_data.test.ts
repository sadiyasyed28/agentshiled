import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mapSimulationHistoryToRuns, EMPTY_BENCHMARK_RUN } from '../src/components/benchmarks/mapSimulationHistory.ts';
import { INITIAL_BENCHMARK_RUNS } from '../src/components/benchmarks/benchmarkData.ts';
import { INITIAL_PENDING_REQUESTS } from '../src/components/review/reviewData.ts';
import type { ApiSimulationRun } from '../src/api/client.ts';

describe('Milestone 1: Honest Dashboard Data & State Integrity', () => {
  it('EMPTY_BENCHMARK_RUN has strict zero counts and no hardcoded numbers', () => {
    assert.strictEqual(EMPTY_BENCHMARK_RUN.total, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.blocked, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.fp, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.bypasses, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.allowedCount, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.reviewCount, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.blockedCount, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.benignCases, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.maliciousCases, 0);
    assert.strictEqual(EMPTY_BENCHMARK_RUN.categoryResults.length, 0);
  });

  it('mapSimulationHistoryToRuns returns empty array for null/empty history', () => {
    assert.deepStrictEqual(mapSimulationHistoryToRuns([]), []);
    assert.deepStrictEqual(mapSimulationHistoryToRuns(null as unknown as ApiSimulationRun[]), []);
  });

  it('maps real simulation history items into honest benchmark records', () => {
    const now = Math.floor(Date.now() / 1000);
    const mockHistory: ApiSimulationRun[] = [
      {
        run_id: 'sim_1',
        scenario_id: 'tool_sqli',
        scenario_name: 'SQL Injection via tool arguments',
        attack_category: 'Injection',
        timestamp: now,
        actual_decision: 'BLOCK',
        expected_decision: 'BLOCK',
        expectation_matched: true,
        risk_score: 95,
        latency_ms: 12.4,
        reasons: ['SQL injection detected'],
        rules_triggered: ['rule_deny_sqli'],
        execution_status: 'COMPLETED',
      },
      {
        run_id: 'sim_2',
        scenario_id: 'benign_read',
        scenario_name: 'Safe file read',
        attack_category: 'Normal authorized actions',
        timestamp: now - 10, // within 120s window -> same batch
        actual_decision: 'ALLOW',
        expected_decision: 'ALLOW',
        expectation_matched: true,
        risk_score: 10,
        latency_ms: 3.2,
        reasons: ['Allowed by policy'],
        rules_triggered: [],
        execution_status: 'COMPLETED',
      },
      {
        run_id: 'sim_3',
        scenario_id: 'false_positive_candidate',
        scenario_name: 'Overly strict block on safe tool',
        attack_category: 'General',
        timestamp: now - 20, // within 120s window -> same batch
        actual_decision: 'BLOCK',
        expected_decision: 'ALLOW', // FP: expected ALLOW but received BLOCK
        expectation_matched: false,
        risk_score: 75,
        latency_ms: 5.1,
        reasons: ['Suspicious pattern'],
        rules_triggered: ['rule_strict'],
        execution_status: 'COMPLETED',
      },
    ];

    const records = mapSimulationHistoryToRuns(mockHistory);
    assert.strictEqual(records.length, 1, 'Should group into single batch run record');

    const run = records[0];
    assert.strictEqual(run.total, 3);
    assert.strictEqual(run.blocked, 2);
    assert.strictEqual(run.allowedCount, 1);
    assert.strictEqual(run.reviewCount, 0);
    assert.strictEqual(run.benignCases, 2); // 2 expected ALLOW
    assert.strictEqual(run.maliciousCases, 1); // 1 expected BLOCK
    assert.strictEqual(run.fp, 1, 'Should accurately detect 1 false positive');
    assert.strictEqual(run.bypasses, 0, 'Should detect 0 bypasses');
    assert.strictEqual(run.status, 'Completed');
    assert.strictEqual(run.categoryResults.length, 3);
  });

  it('separates batches that are executed more than 120 seconds apart', () => {
    const now = Math.floor(Date.now() / 1000);
    const mockHistory: ApiSimulationRun[] = [
      {
        run_id: 'sim_batch1',
        scenario_id: 'scen_1',
        scenario_name: 'Batch 1 scenario',
        attack_category: 'Injection',
        timestamp: now,
        actual_decision: 'BLOCK',
        expected_decision: 'BLOCK',
        expectation_matched: true,
        latency_ms: 10,
        reasons: [],
        rules_triggered: [],
        execution_status: 'COMPLETED',
      },
      {
        run_id: 'sim_batch2',
        scenario_id: 'scen_2',
        scenario_name: 'Batch 2 scenario',
        attack_category: 'Injection',
        timestamp: now - 3600, // 1 hour earlier -> separate batch
        actual_decision: 'ALLOW',
        expected_decision: 'ALLOW',
        expectation_matched: true,
        latency_ms: 5,
        reasons: [],
        rules_triggered: [],
        execution_status: 'COMPLETED',
      },
    ];

    const records = mapSimulationHistoryToRuns(mockHistory);
    assert.strictEqual(records.length, 2, 'Should split into 2 separate benchmark run records');
    assert.strictEqual(records[0].total, 1);
    assert.strictEqual(records[1].total, 1);
  });

  it('preserves reference test suites for automated test baselines', () => {
    assert.ok(INITIAL_BENCHMARK_RUNS.length >= 3, 'Reference benchmark baseline suite must remain available');
    assert.strictEqual(INITIAL_BENCHMARK_RUNS[0].total, 32);
    assert.strictEqual(INITIAL_BENCHMARK_RUNS[0].benignCases, 16);
    assert.strictEqual(INITIAL_BENCHMARK_RUNS[0].maliciousCases, 16);

    assert.ok(INITIAL_PENDING_REQUESTS.length > 0, 'Reference review fixtures must remain available');
  });
});

