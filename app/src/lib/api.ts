const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';
const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8080/stream';

export interface UploadResponse {
  session_id: string;
}

export interface StatusResponse {
  session_id: string;
  status: string;
  state: Record<string, any>;
}

export interface AttackChain {
  category: string;
  sink: string;
  path: string[];
  description?: string;
}

export interface AdjacencyRow {
  function: string;
  calls: string[];
}

export interface CallGraphRaw {
  ok?: boolean;
  nodes?: { name: string; address: string | number; size?: number }[];
  edges?: { from: string | number; to: string | number; from_name?: string; to_name?: string; type?: string }[];
  entry_points?: (string | number)[];
}

export interface CallGraphAnalysis {
  ok?: boolean;
  entries?: string[];
  adjacency?: AdjacencyRow[];
  chains?: AttackChain[];
  cycles?: string[][];
  stats?: {
    nodes?: number;
    edges?: number;
    entries?: number;
    chains?: number;
    cycles?: number;
  };
}

export interface AnalyzerRawResults {
  analyzer: 'ghidra' | 'radare2' | string;
  binary?: Record<string, any>;
  functions?: Record<string, any>;
  strings?: Record<string, any>;
  call_graph?: CallGraphRaw;
  call_graph_analysis?: CallGraphAnalysis;
  decompiled?: Record<string, string>;
}

// Upload a binary file for analysis
export async function uploadBinary(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API_BASE}/analyze/upload`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
  return res.json();
}

// Analyze a binary already on the server
export async function analyzePath(binaryPath: string): Promise<UploadResponse> {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ binary_path: binaryPath }),
  });
  if (!res.ok) throw new Error(`Analyze failed: ${res.status}`);
  return res.json();
}

// Get session status + full state
export async function getStatus(sessionId: string): Promise<StatusResponse> {
  const res = await fetch(`${API_BASE}/status/${sessionId}`);
  if (!res.ok) throw new Error(`Status failed: ${res.status}`);
  return res.json();
}

// Send a natural-language query
export interface QueryResponse {
  ok: boolean;
  answer?: string;
  error?: string;
}

export async function sendQuery(sessionId: string, query: string): Promise<QueryResponse> {
  const res = await fetch(`${API_BASE}/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, query }),
  });
  if (!res.ok) throw new Error(`Query failed: ${res.status}`);
  return res.json();
}

// Get analysis data by program hash
export async function getAnalysis(hash: string) {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getAnalyzers(hash: string) {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/analyzers`);
  if (!res.ok) return [];
  return res.json();
}

export async function getFiles(hash: string) {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/files`);
  if (!res.ok) return null;
  return res.json();
}

export async function getFileContent(hash: string, fileId: string) {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/files/${fileId}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getReports(hash: string) {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/reports`);
  if (!res.ok) return [];
  return res.json();
}

export async function getReportContent(hash: string, reportId: string) {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/reports/${reportId}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getGhidraResults(hash: string): Promise<AnalyzerRawResults | null> {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/results/ghidra`);
  if (!res.ok) return null;
  return res.json();
}

export async function getRadare2Results(hash: string): Promise<AnalyzerRawResults | null> {
  const res = await fetch(`${API_BASE}/api/analysis/${hash}/results/radare2`);
  if (!res.ok) return null;
  return res.json();
}

export async function getModels() {
  const res = await fetch(`${API_BASE}/api/models`);
  if (!res.ok) return [];
  return res.json();
}

// WebSocket connection for real-time events
export function connectStream(sessionId: string, onEvent: (event: any) => void): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/${sessionId}`);
  ws.onmessage = (e) => {
    try {
      onEvent(JSON.parse(e.data));
    } catch {}
  };
  return ws;
}

// Poll status until completed or error, with callback on each poll
export async function pollStatus(
  sessionId: string,
  onUpdate: (status: StatusResponse) => void,
  intervalMs = 5000,
  maxPolls = 540,
): Promise<StatusResponse> {
  for (let i = 0; i < maxPolls; i++) {
    const status = await getStatus(sessionId);
    onUpdate(status);
    if (status.status === 'completed' || status.status === 'error') {
      return status;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error('Polling timed out');
}
