import { describe, expect, it } from 'vitest';

import {
  createEmptyTimingStore,
  estimateEtaSeconds,
  estimateEtaSecondsWithHistory,
  normalizePhaseKey,
  phaseFactor,
  phaseLabel,
  recordPhaseTiming,
  recordTotalTiming,
} from './analyzerProgress';

describe('phaseLabel', () => {
  it('strips analyzer prefixes and formats underscores', () => {
    expect(phaseLabel('ghidra_call_graph_analysis')).toBe('call graph analysis');
    expect(phaseLabel('r2_discovery_completed')).toBe('discovery completed');
    expect(phaseLabel('qiling_emulate_binary')).toBe('emulate binary');
  });

  it('returns empty string for non-string values', () => {
    expect(phaseLabel(undefined)).toBe('');
    expect(phaseLabel(null)).toBe('');
    expect(phaseLabel(123)).toBe('');
  });
});

describe('phaseFactor', () => {
  it('returns expected phase weights', () => {
    expect(phaseFactor('decompile_functions')).toBe(0.55);
    expect(phaseFactor('qiling_emulate_binary')).toBe(0.68);
    expect(phaseFactor('binary_scan')).toBe(0.85);
    expect(phaseFactor('')).toBe(0.85);
    expect(phaseFactor('unknown_step')).toBe(0.8);
  });
});

describe('estimateEtaSeconds', () => {
  it('returns undefined when status is not running', () => {
    expect(estimateEtaSeconds('pending', 40, 30, 'decompile')).toBeUndefined();
    expect(estimateEtaSeconds('completed', 90, 30, 'decompile')).toBeUndefined();
    expect(estimateEtaSeconds('failed', 50, 30, 'decompile')).toBeUndefined();
  });

  it('guards short elapsed time and invalid progress', () => {
    expect(estimateEtaSeconds('running', 50, 3, 'decompile')).toBeUndefined();
    expect(estimateEtaSeconds('running', 2, 20, 'decompile')).toBeUndefined();
    expect(estimateEtaSeconds('running', 100, 20, 'decompile')).toBeUndefined();
    expect(estimateEtaSeconds('running', Number.NaN, 20, 'decompile')).toBeUndefined();
    expect(estimateEtaSeconds('running', Number.POSITIVE_INFINITY, 20, 'decompile')).toBeUndefined();
  });

  it('returns a bounded ETA for valid running progress', () => {
    const eta = estimateEtaSeconds('running', 50, 100, 'qiling_emulate_binary');
    expect(eta).toBe(194);
  });

  it('returns undefined when projection is unrealistically large', () => {
    const eta = estimateEtaSeconds('running', 3, 20000, 'decompile_everything');
    expect(eta).toBeUndefined();
  });
});

describe('timing history', () => {
  it('normalizes phase keys', () => {
    expect(normalizePhaseKey('  QILING_API_TRACE  ')).toBe('qiling_api_trace');
    expect(normalizePhaseKey('')).toBe('working');
  });

  it('records phase/total averages', () => {
    const store = createEmptyTimingStore();
    recordPhaseTiming(store, 'qiling', 'qiling_emulate_binary', 20);
    recordPhaseTiming(store, 'qiling', 'qiling_emulate_binary', 40);
    recordTotalTiming(store, 'qiling', 120);
    recordTotalTiming(store, 'qiling', 60);

    expect(store.qiling.phases.qiling_emulate_binary.avgSeconds).toBe(30);
    expect(store.qiling.phases.qiling_emulate_binary.count).toBe(2);
    expect(store.qiling.total.avgSeconds).toBe(90);
    expect(store.qiling.total.count).toBe(2);
  });

  it('blends heuristic ETA with historical phase timings', () => {
    const store = createEmptyTimingStore();
    recordPhaseTiming(store, 'qiling', 'qiling_emulate_binary', 180);
    recordPhaseTiming(store, 'qiling', 'qiling_parallel_analysis', 60);
    recordTotalTiming(store, 'qiling', 300);

    const eta = estimateEtaSecondsWithHistory({
      status: 'running',
      progressValue: 45,
      elapsedSeconds: 100,
      step: 'qiling_emulate_binary',
      analyzer: 'qiling',
      phaseElapsedSeconds: 70,
      history: store,
    });

    expect(eta).toBeDefined();
    expect(eta).toBeGreaterThan(0);
    expect(eta).toBeLessThan(300);
  });
});
