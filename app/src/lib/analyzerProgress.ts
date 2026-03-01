export type AnalyzerToolStatus = 'pending' | 'running' | 'completed' | 'failed';
export type AnalyzerId = 'ghidra' | 'radare2' | 'qiling';

export interface TimingStat {
  avgSeconds: number;
  count: number;
}

export interface AnalyzerTimingHistory {
  phases: Record<string, TimingStat>;
  total: TimingStat;
}

export type AnalyzerTimingStore = Record<AnalyzerId, AnalyzerTimingHistory>;

export const ANALYZER_TIMING_STORAGE_KEY = 'gireng.analyzerTiming.v1';

const MAX_ETA_SECONDS = 4 * 60 * 60;

const PHASE_ORDER: Record<AnalyzerId, string[]> = {
  ghidra: [
    'initializing_ghidra',
    'discovery_starting',
    'analyzing_binary',
    'listing_functions',
    'extracting_strings',
    'building_call_graph',
    'byte_signatures',
    'decompiling_functions',
    'synthesizing_report',
    'analysis_completed',
  ],
  radare2: [
    'r2_discovery_starting',
    'r2_binary_analysis',
    'r2_listing_functions',
    'r2_parallel_discovery',
    'r2_decompiling',
    'r2_decompile_completed',
    'r2_discovery_completed',
  ],
  qiling: [
    'qiling_discovery_starting',
    'qiling_emulate_binary',
    'qiling_parallel_analysis',
    'qiling_api_trace',
    'qiling_discovery_completed',
  ],
};

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function createEmptyStat(): TimingStat {
  return { avgSeconds: 0, count: 0 };
}

export function createEmptyTimingStore(): AnalyzerTimingStore {
  return {
    ghidra: { phases: {}, total: createEmptyStat() },
    radare2: { phases: {}, total: createEmptyStat() },
    qiling: { phases: {}, total: createEmptyStat() },
  };
}

function updateStat(stat: TimingStat, sampleSeconds: number): TimingStat {
  const sample = Math.max(0, Math.round(sampleSeconds));
  if (!Number.isFinite(sample) || sample <= 0) return stat;
  const nextCount = stat.count + 1;
  const nextAvg = ((stat.avgSeconds * stat.count) + sample) / nextCount;
  return { avgSeconds: Math.round(nextAvg), count: nextCount };
}

function isTimingStat(value: unknown): value is TimingStat {
  if (typeof value !== 'object' || value === null) return false;
  const maybe = value as { avgSeconds?: unknown; count?: unknown };
  return Number.isFinite(Number(maybe.avgSeconds)) && Number.isFinite(Number(maybe.count));
}

export function normalizePhaseKey(raw: string): string {
  const normalized = raw.trim().toLowerCase();
  return normalized || 'working';
}

export function loadTimingStore(): AnalyzerTimingStore {
  if (typeof globalThis === 'undefined' || !('localStorage' in globalThis)) {
    return createEmptyTimingStore();
  }
  try {
    const raw = globalThis.localStorage.getItem(ANALYZER_TIMING_STORAGE_KEY);
    if (!raw) return createEmptyTimingStore();
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const fallback = createEmptyTimingStore();
    for (const analyzer of Object.keys(fallback) as AnalyzerId[]) {
      const maybeAnalyzer = parsed[analyzer] as Record<string, unknown> | undefined;
      if (!maybeAnalyzer || typeof maybeAnalyzer !== 'object') continue;
      const maybeTotal = maybeAnalyzer.total;
      if (isTimingStat(maybeTotal)) {
        fallback[analyzer].total = {
          avgSeconds: Math.max(0, Math.round(Number(maybeTotal.avgSeconds))),
          count: Math.max(0, Math.round(Number(maybeTotal.count))),
        };
      }
      const maybePhases = maybeAnalyzer.phases as Record<string, unknown> | undefined;
      if (!maybePhases || typeof maybePhases !== 'object') continue;
      for (const [phase, stat] of Object.entries(maybePhases)) {
        if (!isTimingStat(stat)) continue;
        fallback[analyzer].phases[normalizePhaseKey(phase)] = {
          avgSeconds: Math.max(0, Math.round(Number(stat.avgSeconds))),
          count: Math.max(0, Math.round(Number(stat.count))),
        };
      }
    }
    return fallback;
  } catch {
    return createEmptyTimingStore();
  }
}

export function saveTimingStore(store: AnalyzerTimingStore): void {
  if (typeof globalThis === 'undefined' || !('localStorage' in globalThis)) return;
  try {
    globalThis.localStorage.setItem(ANALYZER_TIMING_STORAGE_KEY, JSON.stringify(store));
  } catch {
    // Ignore persistence failures; ETA can still use in-memory estimates.
  }
}

export function recordPhaseTiming(
  store: AnalyzerTimingStore,
  analyzer: AnalyzerId,
  phase: string,
  durationSeconds: number,
): AnalyzerTimingStore {
  const phaseKey = normalizePhaseKey(phase);
  const current = store[analyzer].phases[phaseKey] ?? createEmptyStat();
  store[analyzer].phases[phaseKey] = updateStat(current, durationSeconds);
  return store;
}

export function recordTotalTiming(
  store: AnalyzerTimingStore,
  analyzer: AnalyzerId,
  durationSeconds: number,
): AnalyzerTimingStore {
  store[analyzer].total = updateStat(store[analyzer].total, durationSeconds);
  return store;
}

export function phaseLabel(raw: unknown): string {
  const step = asString(raw);
  if (!step) return '';
  const withoutPrefix = step
    .replace(/^ghidra_/, '')
    .replace(/^r2_/, '')
    .replace(/^qiling_/, '');
  return withoutPrefix.replace(/_/g, ' ');
}

export function phaseFactor(step: string): number {
  const s = step.toLowerCase();
  if (!s) return 0.85;
  if (s.includes('decompil')) return 0.55;
  if (s.includes('parallel')) return 0.72;
  if (s.includes('api_trace')) return 0.6;
  if (s.includes('emulate')) return 0.68;
  if (s.includes('byte_signatures')) return 0.75;
  if (s.includes('call_graph')) return 0.78;
  if (s.includes('binary') || s.includes('listing') || s.includes('strings')) return 0.85;
  return 0.8;
}

export function estimateEtaSeconds(
  status: AnalyzerToolStatus,
  progressValue: number,
  elapsedSeconds: number,
  step: string,
): number | undefined {
  if (status !== 'running') return undefined;
  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds <= 3) return undefined;
  if (!Number.isFinite(progressValue) || progressValue < 3 || progressValue >= 100) return undefined;

  const effectiveProgress = Math.max(1, progressValue * phaseFactor(step));
  const projectedTotal = (elapsedSeconds * 100) / effectiveProgress;
  const eta = Math.round(Math.max(0, projectedTotal - elapsedSeconds));
  if (eta > MAX_ETA_SECONDS) return undefined;
  return eta;
}

function sumFuturePhaseAverages(
  analyzer: AnalyzerId,
  currentPhase: string,
  history: AnalyzerTimingStore,
): number {
  const normalizedCurrent = normalizePhaseKey(currentPhase);
  const order = PHASE_ORDER[analyzer];
  const index = order.indexOf(normalizedCurrent);
  if (index === -1) return 0;
  let total = 0;
  for (const phase of order.slice(index + 1)) {
    const stat = history[analyzer].phases[phase];
    if (stat && stat.count > 0 && stat.avgSeconds > 0) total += stat.avgSeconds;
  }
  return total;
}

function estimateEtaFromHistory(
  analyzer: AnalyzerId,
  elapsedSeconds: number,
  step: string,
  phaseElapsedSeconds: number | undefined,
  history: AnalyzerTimingStore | undefined,
): number | undefined {
  if (!history) return undefined;
  const phaseKey = normalizePhaseKey(step);
  const phaseStat = history[analyzer].phases[phaseKey];
  const totalStat = history[analyzer].total;

  let estimate = 0;
  let hasHistory = false;

  if (phaseStat && phaseStat.count > 0 && phaseStat.avgSeconds > 0) {
    const elapsedInPhase = Number.isFinite(phaseElapsedSeconds ?? Number.NaN)
      ? Math.max(0, Math.round(phaseElapsedSeconds ?? 0))
      : 0;
    estimate += Math.max(0, phaseStat.avgSeconds - elapsedInPhase);
    hasHistory = true;
  }

  const future = sumFuturePhaseAverages(analyzer, phaseKey, history);
  if (future > 0) {
    estimate += future;
    hasHistory = true;
  }

  if (!hasHistory && totalStat.count > 0 && totalStat.avgSeconds > 0) {
    estimate = Math.max(0, totalStat.avgSeconds - Math.max(0, Math.round(elapsedSeconds)));
    hasHistory = true;
  }

  if (!hasHistory) return undefined;
  return Math.round(estimate);
}

export function estimateEtaSecondsWithHistory(params: {
  status: AnalyzerToolStatus;
  progressValue: number;
  elapsedSeconds: number;
  step: string;
  analyzer: AnalyzerId;
  phaseElapsedSeconds?: number;
  history?: AnalyzerTimingStore;
}): number | undefined {
  const heuristic = estimateEtaSeconds(params.status, params.progressValue, params.elapsedSeconds, params.step);
  const fromHistory = estimateEtaFromHistory(
    params.analyzer,
    params.elapsedSeconds,
    params.step,
    params.phaseElapsedSeconds,
    params.history,
  );

  let eta: number | undefined;
  if (heuristic !== undefined && fromHistory !== undefined) {
    // Blend current run progress and historical phase timings.
    eta = Math.round((heuristic * 0.45) + (fromHistory * 0.55));
  } else if (fromHistory !== undefined) {
    eta = fromHistory;
  } else {
    eta = heuristic;
  }

  if (eta === undefined) return undefined;
  if (!Number.isFinite(eta) || eta < 0 || eta > MAX_ETA_SECONDS) return undefined;
  return Math.round(eta);
}
