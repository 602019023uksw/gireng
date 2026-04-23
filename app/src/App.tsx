import { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { PanelRight, ArrowLeft } from 'lucide-react';

import { useAuth } from '@/hooks/useAuth';
import { AuthPage } from '@/components/auth/AuthPage';
import { UserMenu } from '@/components/auth/UserMenu';
import { AdminPanel } from '@/components/auth/AdminPanel';

import { Sidebar } from '@/components/layout/Sidebar';
import { MainLayout } from '@/components/layout/MainLayout';
import { ResizablePanel } from '@/components/layout/ResizablePanel';
import { TabbedPanel } from '@/components/layout/TabbedPanel';
import { WelcomeScreen } from '@/components/chat/WelcomeScreen';
import { ChatInterface } from '@/components/chat/ChatInterface';
import { AnalysisHeader } from '@/components/analysis/AnalysisHeader';
import { AnalysisTabs } from '@/components/analysis/AnalysisTabs';
import { AnalyzerList } from '@/components/analysis/AnalyzerList';
import { AnalysisSection } from '@/components/analysis/AnalysisSection';
import CallGraphView from '@/components/analysis/CallGraphView';
import { DataTable } from '@/components/data/DataTable';

import { ModelSelector } from '@/components/chat/ModelSelector';
import { MarkdownContent } from '@/components/common/MarkdownContent';
import {
  estimateEtaSecondsWithHistory,
  loadTimingStore,
  normalizePhaseKey,
  phaseLabel,
  recordPhaseTiming,
  recordTotalTiming,
  saveTimingStore,
  type AnalyzerId,
  type AnalyzerTimingStore,
} from '@/lib/analyzerProgress';

import {
  uploadBinary,
  sendQuery,
  pollStatus,
  connectStream,
  getAnalysis,
  getAnalyzers,
  getFiles,
  getFileContent,
  getReports,
  getReportContent,
  getGhidraResults,
  getRadare2Results,
  getQilingResults,
  getSimilarFiles,
  getHexDump,
  getDisassembly,
  getExportHtmlUrl,
  type CallGraphAnalysis,
  type CallGraphRaw,
} from '@/lib/api';

import {
  mockQuickActions,
  mockAnalysisResult,
} from '@/data/mockData';

import type { Message, Analyzer, FileNode, CodeFile, Report, Analysis, ToolCall, SimilarFile } from '@/types';
import { QilingResultsView } from '@/components/analysis/QilingResultsView';
import type { AnalyzerRawResults } from '@/lib/api';

type ViewState = 'welcome' | 'chat' | 'analysis' | 'admin';
type RightPanelTab = 'resources' | 'code' | 'report' | 'dynamic';
type CallGraphPanel = {
  source: 'Ghidra' | 'Radare2';
  analysis: CallGraphAnalysis;
  rawGraph?: CallGraphRaw;
};
type AnalyzerPhaseElapsed = Partial<Record<AnalyzerId, number>>;

// currentUser is now provided by useAuth()

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function getArrayLength(value: unknown): number {
  return Array.isArray(value) ? value.length : 0;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return {};
  return value as Record<string, unknown>;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function hasAnalyzerData(value: unknown): boolean {
  const record = asRecord(value);
  return Object.keys(record).length > 0;
}

function asToolStatus(value: unknown): ToolCall['status'] | null {
  if (value === 'pending' || value === 'running' || value === 'completed' || value === 'failed') {
    return value;
  }
  return null;
}

function clampPercent(value: number): number {
  return Math.max(0, Math.min(100, value));
}

function deriveAnalyzerToolCalls(
  state: Record<string, unknown>,
  progress: number,
  overallStatus: string,
  elapsedSeconds = 0,
  options?: { timingHistory?: AnalyzerTimingStore; phaseElapsedSeconds?: AnalyzerPhaseElapsed },
): ToolCall[] {
  const trace = asStringArray(state.reasoning_trace);
  const analysisResults = asRecord(state.analysis_results);
  const ghidraCompleted =
    overallStatus === 'completed' ||
    trace.includes('discovery_completed') ||
    hasAnalyzerData(analysisResults);
  const r2Completed = trace.includes('r2_discovery_completed') || hasAnalyzerData(state.r2_analysis_results);
  const qilingCompleted = trace.includes('qiling_discovery_completed') || hasAnalyzerData(state.qiling_analysis_results);
  const r2Failed = trace.includes('r2_unavailable') || trace.some((item) => item.startsWith('r2_error:'));
  const qilingFailed = trace.includes('qiling_unavailable') || trace.some((item) => item.startsWith('qiling_error:'));
  const globalFailed = overallStatus === 'error';
  const analyzerProgress = asRecord(state.analyzer_progress);
  const analyzerStatus = asRecord(state.analyzer_status);
  const analyzerStep = asRecord(state.analyzer_step);

  const resolveStatus = (
    completed: boolean,
    failed: boolean,
    readyHint: boolean,
  ): ToolCall['status'] => {
    if (failed || globalFailed) return 'failed';
    if (completed) return 'completed';
    if (readyHint) return 'running';
    return 'pending';
  };

  const fallbackGhidraStatus = resolveStatus(
    ghidraCompleted,
    false,
    trace.includes('ghidra_initialized') || overallStatus === 'running',
  );
  const fallbackR2Status = resolveStatus(
    r2Completed,
    r2Failed,
    trace.includes('r2_initialized'),
  );
  const fallbackQilingStatus = resolveStatus(
    qilingCompleted,
    qilingFailed,
    trace.includes('qiling_initialized'),
  );

  const ghidraStatus = asToolStatus(analyzerStatus.ghidra) ?? fallbackGhidraStatus;
  const r2Status = asToolStatus(analyzerStatus.radare2) ?? fallbackR2Status;
  const qilingStatus = asToolStatus(analyzerStatus.qiling) ?? fallbackQilingStatus;

  const statusProgress = (status: ToolCall['status'], progressValue: unknown): number => {
    if (status === 'completed') return 100;
    if (status === 'failed' || status === 'pending') return 0;
    const raw = Number(progressValue);
    if (Number.isFinite(raw)) return clampPercent(raw);
    return clampPercent(progress);
  };

  const ghidraProgress = statusProgress(ghidraStatus, analyzerProgress.ghidra);
  const r2Progress = statusProgress(r2Status, analyzerProgress.radare2);
  const qilingProgress = statusProgress(qilingStatus, analyzerProgress.qiling);
  const ghidraStep = asString(analyzerStep.ghidra);
  const r2Step = asString(analyzerStep.radare2);
  const qilingStep = asString(analyzerStep.qiling);
  const phaseElapsed = options?.phaseElapsedSeconds ?? {};
  const timingHistory = options?.timingHistory;

  return [
    {
      id: 'analyzer-ghidra',
      name: 'Ghidra Analysis',
      status: ghidraStatus,
      progress: ghidraProgress,
      maxProgress: 100,
      phase: phaseLabel(ghidraStep),
      etaSeconds: estimateEtaSecondsWithHistory({
        status: ghidraStatus,
        progressValue: ghidraProgress,
        elapsedSeconds,
        step: ghidraStep,
        analyzer: 'ghidra',
        phaseElapsedSeconds: phaseElapsed.ghidra,
        history: timingHistory,
      }),
    },
    {
      id: 'analyzer-radare2',
      name: 'Radare2 Analysis',
      status: r2Status,
      progress: r2Progress,
      maxProgress: 100,
      phase: phaseLabel(r2Step),
      etaSeconds: estimateEtaSecondsWithHistory({
        status: r2Status,
        progressValue: r2Progress,
        elapsedSeconds,
        step: r2Step,
        analyzer: 'radare2',
        phaseElapsedSeconds: phaseElapsed.radare2,
        history: timingHistory,
      }),
    },
    {
      id: 'analyzer-qiling',
      name: 'Qiling Dynamic Analysis',
      status: qilingStatus,
      progress: qilingProgress,
      maxProgress: 100,
      phase: phaseLabel(qilingStep),
      etaSeconds: estimateEtaSecondsWithHistory({
        status: qilingStatus,
        progressValue: qilingProgress,
        elapsedSeconds,
        step: qilingStep,
        analyzer: 'qiling',
        phaseElapsedSeconds: phaseElapsed.qiling,
        history: timingHistory,
      }),
    },
  ];
}

function App() {
  const { user, isAuthenticated, isLoading, isAdmin, login, register, logout } = useAuth();
  const [viewState, setViewState] = useState<ViewState>('welcome');
  const [selectedModelId, setSelectedModelId] = useState('glm-5');
  const [messages, setMessages] = useState<Message[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'analyzers' | 'callgraph' | 'dynamic'>('overview');
  const [rightPanelOpen, setRightPanelOpen] = useState(true);
  const [rightPanelTab, setRightPanelTab] = useState<RightPanelTab>('resources');
  const [activeCodeFileId, setActiveCodeFileId] = useState<string>('');
  const [rightPanelWidth, setRightPanelWidth] = useState(400);
  
  const [currentAnalysis, setCurrentAnalysis] = useState(mockAnalysisResult);
  const [analyzers, setAnalyzers] = useState<Analyzer[]>([]);
  const [fileTree, setFileTree] = useState<FileNode[]>([]);
  const [codeFiles, setCodeFiles] = useState<CodeFile[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [activeReport, setActiveReport] = useState<Report | null>(null);
  const [callGraphPanels, setCallGraphPanels] = useState<CallGraphPanel[]>([]);
  const [qilingResults, setQilingResults] = useState<AnalyzerRawResults | null>(null);
  const [similarFiles, setSimilarFiles] = useState<SimilarFile[]>([]);
  const [codeViewMode, setCodeViewMode] = useState<'decompiled' | 'disassembly' | 'hex'>('decompiled');

  // Track current session
  const sessionRef = useRef<{ id: string; hash: string } | null>(null);
  // Track active upload resources for cancellation
  const activeStreamRef = useRef<WebSocket | null>(null);
  const activeUploadAbortRef = useRef<AbortController | null>(null);

  // Fetch report content when a report is selected
  const handleReportSelect = useCallback(async (reportId: string) => {
    const hash = sessionRef.current?.hash;
    if (!hash) return;
    try {
      const data = await getReportContent(hash, reportId);
      if (data) {
        setActiveReport(data);
      }
    } catch (err) {
      console.error('Failed to fetch report content:', err);
    }
  }, []);

  // Extract a hex address from a function file name like "FUN_180001000.c" -> "0x180001000"
  const deriveFunctionAddress = useCallback((fileName: string): string => {
    const base = fileName.replace(/\.c$/, '');
    // Match FUN_<hex> or similar patterns
    const match = base.match(/(?:0x)?([0-9a-fA-F]{4,})/);
    if (match) {
      return `0x${match[1]}`;
    }
    // If it looks like a raw hex string, use it directly
    if (/^[0-9a-fA-F]{4,}$/.test(base)) {
      return `0x${base}`;
    }
    return base || 'entry0';
  }, []);

  // Fetch hex or disassembly when view mode changes
  const handleCodeViewModeChange = useCallback(async (mode: 'decompiled' | 'disassembly' | 'hex') => {
    setCodeViewMode(mode);
    const hash = sessionRef.current?.hash;
    const file = codeFiles.find(f => f.id === activeCodeFileId);
    if (!hash || !file) return;

    if (mode === 'hex' && !file.hexDump) {
      try {
        const addr = deriveFunctionAddress(file.name);
        const data = await getHexDump(hash, addr, 256);
        if (data) {
          setCodeFiles(prev => prev.map(cf =>
            cf.id === file.id ? { ...cf, hexDump: data } : cf
          ));
        }
      } catch (err) {
        console.error('Failed to fetch hex dump:', err);
      }
    } else if (mode === 'disassembly' && !file.disassembly) {
      try {
        const addr = deriveFunctionAddress(file.name);
        const data = await getDisassembly(hash, addr, 32);
        if (data) {
          setCodeFiles(prev => prev.map(cf =>
            cf.id === file.id ? { ...cf, disassembly: data } : cf
          ));
        }
      } catch (err) {
        console.error('Failed to fetch disassembly:', err);
      }
    }
  }, [codeFiles, activeCodeFileId, deriveFunctionAddress]);

  // Auto-fetch hex/disassembly when switching files while already in those modes
  useEffect(() => {
    const hash = sessionRef.current?.hash;
    const file = codeFiles.find(f => f.id === activeCodeFileId);
    if (!hash || !file) return;

    if (codeViewMode === 'hex' && !file.hexDump) {
      const addr = deriveFunctionAddress(file.name);
      getHexDump(hash, addr, 256).then(data => {
        if (data) {
          setCodeFiles(prev => prev.map(cf =>
            cf.id === file.id ? { ...cf, hexDump: data } : cf
          ));
        }
      }).catch(err => console.error('Auto hex fetch failed:', err));
    } else if (codeViewMode === 'disassembly' && !file.disassembly) {
      const addr = deriveFunctionAddress(file.name);
      getDisassembly(hash, addr, 32).then(data => {
        if (data) {
          setCodeFiles(prev => prev.map(cf =>
            cf.id === file.id ? { ...cf, disassembly: data } : cf
          ));
        }
      }).catch(err => console.error('Auto disasm fetch failed:', err));
    }
  }, [activeCodeFileId, codeViewMode, codeFiles, deriveFunctionAddress]);

  // Fetch all side-panel data for a completed analysis
  // Returns the number of analyzers fetched
  const fetchAnalysisData = useCallback(async (hash: string): Promise<number> => {
    try {
      const [analysisInfo, analyzersData, filesData, reportsData, ghidraResults, radare2Results, qilingResults, similarFilesData] = await Promise.all([
        getAnalysis(hash),
        getAnalyzers(hash),
        getFiles(hash),
        getReports(hash),
        getGhidraResults(hash),
        getRadare2Results(hash),
        getQilingResults(hash),
        getSimilarFiles(hash),
      ]);
      setAnalyzers(analyzersData || []);
      if (filesData?.children) {
        setFileTree(filesData.children);
        // Fetch content for each code file
        const codeFilePromises = (filesData.children as FileNode[]).map((f: FileNode) =>
          getFileContent(hash, f.id).then((cf) => cf as CodeFile | null)
        );
        const cfs = (await Promise.all(codeFilePromises)).filter(Boolean) as CodeFile[];
        setCodeFiles(cfs);
      }
      setReports(reportsData || []);

      // Auto-load the first report content for the Analysis Summary
      if (reportsData?.length > 0) {
        try {
          const firstReport = await getReportContent(hash, reportsData[0].id);
          if (firstReport) setActiveReport(firstReport);
        } catch { /* non-critical */ }
      }

      // Derive overall verdict from analyzers: worst-case wins
      const verdictPriority: Record<string, number> = { 'Malware': 3, 'Suspicious': 2, 'Clean': 1 };
      const overallVerdict = (analyzersData || []).reduce(
        (worst: string, a: Analyzer) => {
          const p = verdictPriority[a.verdict] || 0;
          return p > (verdictPriority[worst] || 0) ? a.verdict : worst;
        },
        'Clean',
      );

      // Use real threat score and tags from the API when available,
      // with fallback to the coarse verdict-based score.
      const apiVerdict = analysisInfo?.verdict ?? overallVerdict;
      const apiThreatScore = typeof analysisInfo?.threatScore === 'number'
        ? analysisInfo.threatScore : ({ 'Malware': 6, 'Suspicious': 3, 'Clean': 0 } as Record<string, number>)[overallVerdict] ?? 0;
      const apiMaxScore = typeof analysisInfo?.maxScore === 'number' ? analysisInfo.maxScore : 100;
      const apiTags: string[] = Array.isArray(analysisInfo?.tags) ? analysisInfo.tags : [];
      // Inject malware type as first tag if present
      if (analysisInfo?.malwareType && !apiTags.includes(analysisInfo.malwareType)) {
        apiTags.unshift(analysisInfo.malwareType);
      }

      setCurrentAnalysis(prev => ({
        ...prev,
        verdict: apiVerdict,
        threatScore: apiThreatScore,
        maxScore: apiMaxScore,
        tags: apiTags,
        ...(analysisInfo?.duration ? { duration: analysisInfo.duration } : {}),
        ...(analysisInfo?.started ? { started: new Date(analysisInfo.started).toLocaleString() } : {}),
        ...(analysisInfo?.completed ? { completed: new Date(analysisInfo.completed).toLocaleString() } : {}),
      }));

      const callGraphData: CallGraphPanel[] = [];
      const ghAnalysis = ghidraResults?.call_graph_analysis;
      if (ghAnalysis?.ok) {
        callGraphData.push({ source: 'Ghidra', analysis: ghAnalysis, rawGraph: ghidraResults?.call_graph });
      }
      const r2Analysis = radare2Results?.call_graph_analysis;
      if (r2Analysis?.ok) {
        callGraphData.push({ source: 'Radare2', analysis: r2Analysis, rawGraph: radare2Results?.call_graph });
      }
      setCallGraphPanels(callGraphData);

      // Store Qiling dynamic analysis results
      setQilingResults(qilingResults);

      // Store similar files
      setSimilarFiles(
        (similarFilesData || []).map((s) => ({ id: s.hash, hash: s.hash, labels: s.labels }))
      );

      const analyzerTags = (analyzersData || []).map((a: Analyzer) => a.name.split(' ')[0].toLowerCase());
      const hasQilingPayload =
        Boolean(qilingResults?.execution_trace) ||
        Boolean(qilingResults?.syscalls) ||
        Boolean(qilingResults?.network_activity);
      if (hasQilingPayload && !analyzerTags.includes('qiling')) {
        analyzerTags.push('qiling');
      }

      setAnalyses([{
        id: hash,
        hash,
        shortHash: hash.slice(0, 16) + '...',
        tags: analyzerTags,
        extraTagCount: 0,
        verdict: overallVerdict,
        status: 'completed',
      }]);
      return (analyzersData || []).length;
    } catch (err) {
      console.error('Failed to fetch analysis data:', err);
      return 0;
    }
  }, []);

  // Handle file upload (drag-and-drop or file picker)
  const handleFileUpload = useCallback(async (file: File) => {
    // Cancel any previous upload
    if (activeUploadAbortRef.current) {
      activeUploadAbortRef.current.abort();
      activeUploadAbortRef.current = null;
    }
    if (activeStreamRef.current) {
      try {
        activeStreamRef.current.close();
      } catch {
        // no-op
      }
      activeStreamRef.current = null;
    }
    activeUploadAbortRef.current = new AbortController();

    let stream: WebSocket | null = null;

    const uploadMsg: Message = {
      id: Date.now().toString(),
      content: `Uploading binary: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`,
      isUser: true,
      timestamp: new Date(),
    };
    setMessages(prev => [...prev, uploadMsg]);
    setViewState('chat');

    try {
      const { session_id } = await uploadBinary(file, selectedModelId);
      const analyzingMsg: Message = {
        id: (Date.now() + 1).toString(),
        content:
          `Binary uploaded. Analyzing **${file.name}** with Ghidra, Radare2, and Qiling... This typically takes 5-15 minutes.\n\n` +
          `**starting** - 0%`,
        isUser: false,
        timestamp: new Date(),
        toolCalls: deriveAnalyzerToolCalls({}, 0, 'running'),
      };
      setMessages(prev => [...prev, analyzingMsg]);

      const startTime = Date.now();
      let latestState: Record<string, unknown> = {};
      let latestStep = 'starting';
      let latestProgress = 0;
      let latestStatus = 'running';
      let timingHistory = loadTimingStore();

      type AnalyzerTracker = { phase: string; phaseStartedAtMs: number; finalized: boolean };
      const analyzerTrackers: Partial<Record<AnalyzerId, AnalyzerTracker>> = {};
      const analyzerIds: AnalyzerId[] = ['ghidra', 'radare2', 'qiling'];

      const statusFromToolCalls = (toolCalls: ToolCall[]): Partial<Record<AnalyzerId, ToolCall['status']>> => {
        const statusMap: Partial<Record<AnalyzerId, ToolCall['status']>> = {};
        for (const tool of toolCalls) {
          if (tool.id === 'analyzer-ghidra') statusMap.ghidra = tool.status;
          if (tool.id === 'analyzer-radare2') statusMap.radare2 = tool.status;
          if (tool.id === 'analyzer-qiling') statusMap.qiling = tool.status;
        }
        return statusMap;
      };

      const getPhaseElapsedSeconds = (nowMs: number): AnalyzerPhaseElapsed => {
        const phaseElapsed: AnalyzerPhaseElapsed = {};
        for (const analyzer of analyzerIds) {
          const tracker = analyzerTrackers[analyzer];
          if (!tracker || tracker.finalized) continue;
          phaseElapsed[analyzer] = Math.max(0, Math.round((nowMs - tracker.phaseStartedAtMs) / 1000));
        }
        return phaseElapsed;
      };

      const syncTimingHistory = (
        nowMs: number,
        analyzerStep: Record<string, unknown>,
        toolCalls: ToolCall[],
        totalElapsedSeconds: number,
      ): boolean => {
        const statusMap = statusFromToolCalls(toolCalls);
        let trackerChanged = false;
        let historyChanged = false;

        for (const analyzer of analyzerIds) {
          const status = statusMap[analyzer];
          const phaseRaw = asString(analyzerStep[analyzer], 'working');
          const phaseKey = normalizePhaseKey(phaseRaw);
          const tracker = analyzerTrackers[analyzer];

          if (status === 'running') {
            if (!tracker) {
              analyzerTrackers[analyzer] = { phase: phaseKey, phaseStartedAtMs: nowMs, finalized: false };
              trackerChanged = true;
              continue;
            }
            if (tracker.phase !== phaseKey) {
              const phaseDurationSeconds = Math.round((nowMs - tracker.phaseStartedAtMs) / 1000);
              if (phaseDurationSeconds >= 1) {
                timingHistory = recordPhaseTiming(timingHistory, analyzer, tracker.phase, phaseDurationSeconds);
                historyChanged = true;
              }
              tracker.phase = phaseKey;
              tracker.phaseStartedAtMs = nowMs;
              tracker.finalized = false;
              trackerChanged = true;
            }
            continue;
          }

          if ((status === 'completed' || status === 'failed') && tracker && !tracker.finalized) {
            const phaseDurationSeconds = Math.round((nowMs - tracker.phaseStartedAtMs) / 1000);
            if (phaseDurationSeconds >= 1) {
              timingHistory = recordPhaseTiming(timingHistory, analyzer, tracker.phase, phaseDurationSeconds);
              historyChanged = true;
            }
            if (totalElapsedSeconds >= 1) {
              timingHistory = recordTotalTiming(timingHistory, analyzer, totalElapsedSeconds);
              historyChanged = true;
            }
            tracker.finalized = true;
            trackerChanged = true;
          }
        }

        if (historyChanged) saveTimingStore(timingHistory);
        return trackerChanged || historyChanged;
      };

      const updateAnalyzingMessage = (
        nextStep?: string,
        nextProgress?: number,
        nextStatus?: string,
        nextState?: Record<string, unknown>,
      ) => {
        if (nextState) latestState = nextState;
        if (nextStep) latestStep = nextStep;
        if (nextStatus) latestStatus = nextStatus;
        if (typeof nextProgress === 'number' && Number.isFinite(nextProgress)) {
          latestProgress = Math.max(0, Math.min(100, nextProgress));
        }
        const nowMs = Date.now();
        const elapsed = Math.round((nowMs - startTime) / 1000);
        const mins = Math.floor(elapsed / 60);
        const secs = elapsed % 60;
        const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
        const analyzerStep = asRecord(latestState.analyzer_step);
        const phaseElapsed = getPhaseElapsedSeconds(nowMs);
        let toolCalls = deriveAnalyzerToolCalls(latestState, latestProgress, latestStatus, elapsed, {
          timingHistory,
          phaseElapsedSeconds: phaseElapsed,
        });
        const changed = syncTimingHistory(nowMs, analyzerStep, toolCalls, elapsed);
        if (changed) {
          toolCalls = deriveAnalyzerToolCalls(latestState, latestProgress, latestStatus, elapsed, {
            timingHistory,
            phaseElapsedSeconds: getPhaseElapsedSeconds(nowMs),
          });
        }
        setMessages(prev =>
          prev.map(m =>
            m.id === analyzingMsg.id
              ? {
                  ...m,
                  content:
                    `Analyzing **${file.name}**... (${timeStr} elapsed)\n\n` +
                    `**${latestStep}** - ${latestProgress}%`,
                  toolCalls,
                }
              : m
          )
        );
      };

      stream = connectStream(session_id, (event) => {
        if (activeUploadAbortRef.current?.signal.aborted) return;
        const evt = asRecord(event);
        const evtType = asString(evt.type);
        const payload = asRecord(evt.payload);
        const payloadState = {
          ...latestState,
          ...(payload.analyzer_progress ? { analyzer_progress: asRecord(payload.analyzer_progress) } : {}),
          ...(payload.analyzer_status ? { analyzer_status: asRecord(payload.analyzer_status) } : {}),
          ...(payload.analyzer_step ? { analyzer_step: asRecord(payload.analyzer_step) } : {}),
        };
        if (evtType === 'analysis:progress') {
          updateAnalyzingMessage(
            asString(payload.step, latestStep),
            Number(payload.progress ?? latestProgress),
            asString(payload.status, 'running'),
            payloadState,
          );
        } else if (evtType === 'analysis:error') {
          updateAnalyzingMessage(
            asString(payload.step, latestStep),
            Number(payload.progress ?? latestProgress),
            'error',
            payloadState,
          );
        } else if (evtType === 'analysis:completed') {
          updateAnalyzingMessage('analysis_completed', 100, 'completed', payloadState);
        }
      });

      const result = await pollStatus(
        session_id,
        (statusUpdate) => {
          const state = asRecord(statusUpdate.state);
          const step = asString(state.current_step, statusUpdate.status || 'analyzing');
          const rawProgress = Number(state.progress ?? 0);
          updateAnalyzingMessage(step, rawProgress, statusUpdate.status, state);
        },
        2000,
        1800,
        activeUploadAbortRef.current?.signal,
      );

      const state = asRecord(result.state);
      const hash = asString(state.program_hash);
      if (!hash) {
        throw new Error('Analysis response is missing program hash');
      }
      sessionRef.current = { id: session_id, hash };
      setCodeViewMode('decompiled');

      // Build result message
      const summary = asString(state.summary, 'Analysis completed.');
      const analysisResults = (state.analysis_results as Record<string, unknown> | undefined) ?? {};
      const functionsResult = (analysisResults.functions as Record<string, unknown> | undefined) ?? {};
      const stringsResult = (analysisResults.strings as Record<string, unknown> | undefined) ?? {};
      const funcCount = getArrayLength(functionsResult.functions);
      const strCount = getArrayLength(stringsResult.strings);

      // Count analyzers: Ghidra always present, R2 if results exist
      const hasR2 = Boolean(analysisResults.r2) || Boolean(state.r2_analysis_results);
      const hasQiling = Boolean(state.qiling_analysis_results);
      const analyzerTotal = 1 + (hasR2 ? 1 : 0) + (hasQiling ? 1 : 0);
      const resultMsg: Message = {
        id: (Date.now() + 2).toString(),
        content: summary + `\n\n---\n**${funcCount}** functions, **${strCount}** strings found.`,
        isUser: false,
        timestamp: new Date(),
        toolCalls: deriveAnalyzerToolCalls(state, 100, result.status),
        showAnalysisCompleted: true,
        analysisHash: hash,
        analyzerCount: analyzerTotal,
        analyzerTotal: analyzerTotal,
      };
      setMessages(prev => {
        // Replace the "analyzing" message with the result
        const filtered = prev.filter(m => m.id !== analyzingMsg.id);
        return [...filtered, resultMsg];
      });

      // Populate side panel data
      const endTime = Date.now();
      const totalSecs = Math.round((endTime - startTime) / 1000);
      const dMins = Math.floor(totalSecs / 60);
      const dSecs = totalSecs % 60;
      const durationStr = dMins > 0 ? `${dMins}m ${dSecs}s` : `${dSecs}s`;
      const startedStr = new Date(startTime).toLocaleString();
      const completedStr = new Date(endTime).toLocaleString();
      setCurrentAnalysis({
        ...mockAnalysisResult,
        hash,
        status: result.status.toUpperCase(),
        type: asString(
          (analysisResults.binary as Record<string, unknown> | undefined)?.architecture,
          'Unknown',
        ),
        verdict: '',
        duration: durationStr,
        started: startedStr,
        completed: completedStr,
      });
      const realAnalyzerCount = await fetchAnalysisData(hash);
      if (realAnalyzerCount > 0) {
        setMessages(prev =>
          prev.map(m =>
            m.id === resultMsg.id
              ? { ...m, analyzerCount: realAnalyzerCount, analyzerTotal: realAnalyzerCount }
              : m
          )
        );
      }
    } catch (err: unknown) {
      const errMsg: Message = {
        id: (Date.now() + 3).toString(),
        content: `Error: ${getErrorMessage(err)}`,
        isUser: false,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errMsg]);
    } finally {
      if (stream) {
        try {
          stream.close();
        } catch {
          // no-op
        }
      }
      activeStreamRef.current = null;
      activeUploadAbortRef.current = null;
    }
  }, [fetchAnalysisData, selectedModelId]);

  const handleSendMessage = useCallback(async (content: string, agentId?: string) => {
    const userMessage: Message = {
      id: Date.now().toString(),
      content,
      isUser: true,
      timestamp: new Date(),
      ...(agentId ? { agentId } : {}),
    };
    setMessages(prev => [...prev, userMessage]);
    setViewState('chat');

    // If no active session, check if this looks like a file upload request
    if (!sessionRef.current) {
      const noSessionMsg: Message = {
        id: (Date.now() + 1).toString(),
        content: 'No binary loaded yet. Please upload a binary file first by dragging it into the chat or using the upload button.',
        isUser: false,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, noSessionMsg]);
      return;
    }

    // Detect report generation commands
    const lower = content.toLowerCase().trim();
    const isReportCommand = /\b(create|generate|export|print|download|make|show)\b.*\b(report|pdf|html)\b/i.test(lower)
      || /\breport\b/i.test(lower) && lower.length < 40;
    if (isReportCommand && sessionRef.current.hash) {
      const reportUrl = getExportHtmlUrl(sessionRef.current.hash);
      window.open(reportUrl, '_blank');
      const reportMsg: Message = {
        id: (Date.now() + 1).toString(),
        content: `Report generated and opened in a new tab. You can also print it to PDF from there.\n\n[Open Report](${reportUrl})`,
        isUser: false,
        timestamp: new Date(),
        toolCalls: [{ id: '1', name: 'Report Generation', status: 'completed' }],
      };
      setMessages(prev => [...prev, reportMsg]);
      return;
    }

    // Send query to backend
    const thinkingMsg: Message = {
      id: (Date.now() + 1).toString(),
      content: 'Analyzing...',
      isUser: false,
      timestamp: new Date(),
      toolCalls: [{ id: '1', name: 'Agent Query', status: 'running' }],
    };
    setMessages(prev => [...prev, thinkingMsg]);

    try {
      const queryResult = await sendQuery(sessionRef.current.id, content, selectedModelId);

      const answer = queryResult.answer || 'No answer returned.';
      const responseMsg: Message = {
        id: (Date.now() + 2).toString(),
        content: answer,
        isUser: false,
        timestamp: new Date(),
        toolCalls: [{ id: '1', name: 'Agent Query', status: 'completed' }],
      };
      setMessages(prev => {
        const filtered = prev.filter(m => m.id !== thinkingMsg.id);
        return [...filtered, responseMsg];
      });

      // Refresh side panel data
      await fetchAnalysisData(sessionRef.current.hash);
    } catch (err: unknown) {
      // If analysis is still running, give a more helpful message
      const msg = getErrorMessage(err);
      const isNotCompleted = msg.includes('400');
      const errContent = isNotCompleted
        ? 'The analysis is still in progress. Please wait for it to complete before asking questions. You can ask follow-up questions once the analysis finishes.'
        : `Error: ${msg}`;
      const errMsg: Message = {
        id: (Date.now() + 3).toString(),
        content: errContent,
        isUser: false,
        timestamp: new Date(),
      };
      setMessages(prev => {
        const filtered = prev.filter(m => m.id !== thinkingMsg.id);
        return [...filtered, errMsg];
      });
    }
  }, [fetchAnalysisData]);

  const handleNewChat = () => {
    setMessages([]);
    sessionRef.current = null;
    setAnalyzers([]);
    setFileTree([]);
    setCodeFiles([]);
    setReports([]);
    setActiveReport(null);
    setAnalyses([]);
    setCallGraphPanels([]);
    setCodeViewMode('decompiled');
    setViewState('welcome');
  };

  // Restore a past session from history sidebar
  const handleRestoreSession = useCallback(async (sessionId: string, programHash: string) => {
    sessionRef.current = { id: sessionId, hash: programHash };
    setCodeViewMode('decompiled');

    const restoredMsg: Message = {
      id: Date.now().toString(),
      content: `Restored past analysis for binary \`${programHash.slice(0, 16)}...\``,
      isUser: false,
      timestamp: new Date(),
    };
    setMessages([restoredMsg]);
    setViewState('chat');

    // Load analysis data from the restored session
    try {
      const analyzerCount = await fetchAnalysisData(programHash);
      const completedMsg: Message = {
        id: (Date.now() + 1).toString(),
        content: `Analysis data loaded. ${analyzerCount} analyzer(s) available. You can ask follow-up questions or view the analysis.`,
        isUser: false,
        timestamp: new Date(),
        showAnalysisCompleted: true,
        analysisHash: programHash,
        analyzerCount,
        analyzerTotal: analyzerCount,
      };
      setMessages(prev => [...prev, completedMsg]);
    } catch {
      const errMsg: Message = {
        id: (Date.now() + 2).toString(),
        content: 'Failed to load analysis data from this session.',
        isUser: false,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errMsg]);
    }
  }, [fetchAnalysisData]);

  const handleQuickAction = useCallback((actionId: string) => {
    const action = mockQuickActions.find(a => a.id === actionId);
    if (!action) return;
    const prompts: Record<string, string> = {
      cves: 'Search for known vulnerable API usage (e.g., strcpy, sprintf, gets) in this binary and map them to CVE patterns.',
      deobfuscate: 'Identify obfuscation techniques used in this binary and attempt to reconstruct the original logic.',
      workflows: 'Outline the execution workflows and behavior chains observed in this binary, including entry points and key decision branches.',
      apt: 'Generate an APT-style threat report focusing on TTPs and MITRE mapping for this binary.',
      hash: 'Research any cryptographic hashes, checksums, or hash-based API usage in this binary and assess their purpose.',
    };
    const prompt = prompts[actionId] || action.label;
    handleSendMessage(prompt);
  }, [handleSendMessage]);

  const handleViewAnalysis = () => {
    setViewState('analysis');
  };

  const handleBackToChat = () => {
    setViewState('chat');
  };

  const renderRightPanel = () => {
    if (!rightPanelOpen) return null;

    return (
      <ResizablePanel
        defaultWidth={rightPanelWidth}
        minWidth={320}
        maxWidth={700}
        onResize={setRightPanelWidth}
      >
        <TabbedPanel
          files={fileTree}
          analyses={analyses}
          reports={reports}
          codeFiles={codeFiles}
          activeTab={rightPanelTab}
          activeCodeFileId={activeCodeFileId}
          activeReport={activeReport}
          programHash={sessionRef.current?.hash ?? null}
          qilingResults={qilingResults}
          codeViewMode={codeViewMode}
          onTabChange={setRightPanelTab}
          onCodeFileChange={setActiveCodeFileId}
          onReportSelect={handleReportSelect}
          onCodeViewModeChange={handleCodeViewModeChange}
          onClose={() => setRightPanelOpen(false)}
        />
      </ResizablePanel>
    );
  };

  // Similar files table columns
  const similarFilesColumns = [
    { key: 'hash', header: 'SHA256 Hash of Similar File', width: '60%' },
    { key: 'labels', header: 'Common Threat Label(s)', width: '40%' },
  ];

  // Similar files table rows - populated from API: GET /api/analysis/:hash/similar
  const similarFilesRows = similarFiles.length > 0
    ? similarFiles.map((file) => ({
        hash: <span className="text-sm font-mono text-text-secondary">{file.hash}</span>,
        labels: (
          <div className="flex flex-wrap gap-1">
            {file.labels.map((label, i) => (
              <span
                key={i}
                className="px-2 py-0.5 rounded text-xs"
                style={{
                  background: 'rgba(168, 85, 247, 0.1)',
                  border: '1px solid rgba(168, 85, 247, 0.2)',
                  color: '#a855f7',
                }}
              >
                {label}
              </span>
            ))}
          </div>
        ),
      }))
    : [];

  // Auth loading spinner
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-bg-primary">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400" />
      </div>
    );
  }

  // Auth gate: show login/register if not authenticated
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-bg-primary">
        <div className="fixed inset-0 pointer-events-none">
          <div
            className="absolute inset-0"
            style={{
              background: `
                radial-gradient(ellipse at 20% 20%, rgba(168, 85, 247, 0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(34, 211, 238, 0.04) 0%, transparent 50%),
                linear-gradient(180deg, #0a0a0f 0%, #0d0d14 100%)
              `,
            }}
          />
        </div>
        <AuthPage onLogin={login} onRegister={register} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg-primary">
      {/* Background gradients */}
      <div className="fixed inset-0 pointer-events-none">
        <div 
          className="absolute inset-0"
          style={{
            background: `
              radial-gradient(ellipse at 20% 20%, rgba(168, 85, 247, 0.06) 0%, transparent 50%),
              radial-gradient(ellipse at 80% 80%, rgba(34, 211, 238, 0.04) 0%, transparent 50%),
              linear-gradient(180deg, #0a0a0f 0%, #0d0d14 100%)
            `,
          }}
        />
      </div>

      <MainLayout
        sidebar={
          <Sidebar
            onNewChat={handleNewChat}
            onRestoreSession={handleRestoreSession}
          />
        }
        rightPanel={renderRightPanel()}
      >
        {/* Top Header - Glass Terminal Style */}
        <header
          className="h-14 flex items-center justify-between px-4 flex-shrink-0 backdrop-blur-xl relative z-30"
          style={{
            background: 'rgba(8, 8, 14, 0.85)',
            borderBottom: '1px solid rgba(100, 100, 150, 0.1)',
          }}
        >
          <div className="flex items-center gap-4">
            {/* Terminal Dots */}
            <div className="flex items-center gap-1.5 mr-2">
              <div className="w-3 h-3 rounded-full bg-terminal-red shadow-[0_0_6px_#ff5f56]" />
              <div className="w-3 h-3 rounded-full bg-terminal-yellow shadow-[0_0_6px_#ffbd2e]" />
              <div className="w-3 h-3 rounded-full bg-terminal-green shadow-[0_0_6px_#27c93f]" />
            </div>

            {/* Back Button (when in analysis view) */}
            {viewState === 'analysis' && (
              <button
                onClick={handleBackToChat}
                className="flex items-center gap-2 px-3 py-1.5 text-text-secondary hover:text-text-primary rounded-lg transition-all duration-150 hover:bg-white/5"
              >
                <ArrowLeft className="w-4 h-4" />
                <span className="text-sm">Back to Chat</span>
              </button>
            )}

            {/* Toggle Right Panel Button */}
            {!rightPanelOpen && (
              <button
                onClick={() => setRightPanelOpen(true)}
                className="flex items-center gap-2 px-3 py-1.5 text-text-secondary hover:text-text-primary rounded-lg transition-all duration-150 hover:bg-white/5"
              >
                <PanelRight className="w-4 h-4" />
                <span className="text-sm">Resources</span>
              </button>
            )}

            {/* Model Selector (in chat mode) */}
            {viewState === 'chat' && (
              <ModelSelector
                selectedModelId={selectedModelId}
                onSelect={setSelectedModelId}
              />
            )}
          </div>

          <div className="flex items-center gap-2">
            {user && (
              <UserMenu
                user={user}
                onLogout={logout}
                onAdminPanel={isAdmin ? () => setViewState('admin') : undefined}
              />
            )}
          </div>
        </header>

        {/* Main Content Area */}
        <div className="flex-1 overflow-hidden relative z-10">
          <AnimatePresence mode="wait">
            {viewState === 'welcome' && (
              <motion.div
                key="welcome"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
                className="h-full relative"
              >
                <WelcomeScreen
                  userName={user?.username ?? ''}
                  selectedModelId={selectedModelId}
                  quickActions={mockQuickActions}
                  onModelSelect={setSelectedModelId}
                  onSendMessage={handleSendMessage}
                  onFileUpload={handleFileUpload}
                  onQuickAction={handleQuickAction}
                />
              </motion.div>
            )}

            {viewState === 'chat' && (
              <motion.div
                key="chat"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
                className="h-full relative"
              >
                <ChatInterface
                  messages={messages}
                  onSendMessage={handleSendMessage}
                  onViewAnalysis={handleViewAnalysis}
                />
              </motion.div>
            )}

            {viewState === 'analysis' && (
              <motion.div
                key="analysis"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
                className="h-full overflow-y-auto scrollbar-dark"
              >
                <div className="max-w-5xl mx-auto p-6">
                  {/* Analysis Header */}
                  <AnalysisHeader analysis={currentAnalysis} />

                  {/* Tabs */}
                  <div className="mt-6">
                    <AnalysisTabs
                      activeTab={activeTab}
                      onTabChange={setActiveTab}
                      hasDynamicData={qilingResults != null}
                    />
                  </div>

                  {/* Tab Content */}
                  <div className="mt-6">
                    {activeTab === 'overview' && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        {/* Similar Files Section - Only show if data exists */}
                        {similarFiles.length > 0 && (
                          <AnalysisSection title="Similar Files Found">
                            <p className="text-sm text-text-secondary mb-4">
                              Similar files found during analysis.
                            </p>
                            <DataTable
                              columns={similarFilesColumns}
                              rows={similarFilesRows}
                            />
                          </AnalysisSection>
                        )}

                        {/* Analysis Summary */}
                        <AnalysisSection title="Analysis Summary">
                          {activeReport?.html_url ? (
                            <div className="w-full" style={{ height: '70vh', minHeight: '500px' }}>
                              <iframe
                                src={activeReport.html_url}
                                className="w-full h-full rounded-lg border-0"
                                style={{ background: '#050915' }}
                                title="Analysis Report"
                                sandbox="allow-scripts allow-same-origin"
                              />
                            </div>
                          ) : activeReport?.content ? (
                            <MarkdownContent content={activeReport.content} compact />
                          ) : (
                            <p className="text-sm text-text-muted italic">
                              Click a report in the Resources panel to view the analysis summary.
                            </p>
                          )}
                        </AnalysisSection>

                      </motion.div>
                    )}

                    {activeTab === 'analyzers' && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <AnalyzerList analyzers={analyzers} />
                      </motion.div>
                    )}

                    {activeTab === 'callgraph' && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <AnalysisSection title="Call Graph & Attack Chains">
                          <CallGraphView panels={callGraphPanels} />
                        </AnalysisSection>
                      </motion.div>
                    )}

                    {activeTab === 'dynamic' && qilingResults && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <AnalysisSection title="Qiling Dynamic Analysis">
                          <QilingResultsView results={qilingResults} />
                        </AnalysisSection>
                      </motion.div>
                    )}
                  </div>
                </div>
              </motion.div>
            )}

            {viewState === 'admin' && isAdmin && (
              <motion.div
                key="admin"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
                className="h-full"
              >
                <AdminPanel
                  onBack={() => setViewState('welcome')}
                  currentUserId={user?.id ?? ''}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </MainLayout>

    </div>
  );
}

export default App;
