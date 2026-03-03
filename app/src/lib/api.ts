const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
const WS_BASE = import.meta.env.VITE_WS_URL
  || `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/stream`;

// ---------------------------------------------------------------------------
// Auth token management
// ---------------------------------------------------------------------------

const TOKEN_KEY = 'gireng_auth_token';

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearStoredToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

/** Build auth headers (exported for custom use). */
export function authHeaders(): Record<string, string> {
  const token = getStoredToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Authenticated fetch wrapper — injects Bearer token automatically. */
async function authFetch(url: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  const token = getStoredToken();
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  return fetch(url, { ...init, headers });
}

// ---------------------------------------------------------------------------
// Auth API
// ---------------------------------------------------------------------------

export interface AuthResponse {
  token: string;
  user: { id: string; email: string; username: string; role: string };
}

export async function apiLogin(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Login failed: ${res.status}`);
  }
  return res.json();
}

export async function apiRegister(email: string, username: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, username, password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Registration failed: ${res.status}`);
  }
  return res.json();
}

export async function apiGetMe(): Promise<{ id: string; email: string; username: string; role: string } | null> {
  const token = getStoredToken();
  if (!token) return null;
  const res = await authFetch(`${API_BASE}/api/auth/me`);
  if (!res.ok) { clearStoredToken(); return null; }
  return res.json();
}

// Admin API
export async function apiGetUsers(limit = 100, offset = 0) {
  const res = await authFetch(`${API_BASE}/api/admin/users?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error('Failed to fetch users');
  return res.json();
}

export async function apiUpdateUserRole(userId: string, role: string) {
  const res = await authFetch(`${API_BASE}/api/admin/users/${userId}/role`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to update role');
  }
  return res.json();
}

export async function apiToggleUserActive(userId: string) {
  const res = await authFetch(`${API_BASE}/api/admin/users/${userId}/active`, { method: 'PUT' });
  if (!res.ok) throw new Error('Failed to toggle user');
  return res.json();
}

export async function apiDeleteUser(userId: string) {
  const res = await authFetch(`${API_BASE}/api/admin/users/${userId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete user');
  return res.json();
}

export interface UploadResponse {
  session_id: string;
}

export interface StatusResponse {
  session_id: string;
  status: string;
  state: Record<string, unknown>;
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
  binary?: Record<string, unknown>;
  functions?: Record<string, unknown>;
  strings?: Record<string, unknown>;
  call_graph?: CallGraphRaw;
  call_graph_analysis?: CallGraphAnalysis;
  decompiled?: Record<string, string>;
  execution_trace?: Record<string, unknown>;
  syscalls?: Record<string, unknown>;
  api_calls?: Record<string, unknown>;
  memory_events?: Record<string, unknown>;
  network_activity?: Record<string, unknown>;
  evasion_techniques?: Record<string, unknown>;
  instruction_trace?: Record<string, unknown>;
  errors?: unknown[];
}

// Upload a binary file for analysis
export async function uploadBinary(file: File): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  const res = await authFetch(`${API_BASE}/analyze/upload`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
  return res.json();
}

// Analyze a binary already on the server
export async function analyzePath(binaryPath: string): Promise<UploadResponse> {
  const res = await authFetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ binary_path: binaryPath }),
  });
  if (!res.ok) throw new Error(`Analyze failed: ${res.status}`);
  return res.json();
}

// Get session status + full state
export async function getStatus(sessionId: string): Promise<StatusResponse> {
  const res = await authFetch(`${API_BASE}/status/${sessionId}`);
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
  const res = await authFetch(`${API_BASE}/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, query }),
  });
  if (!res.ok) throw new Error(`Query failed: ${res.status}`);
  return res.json();
}

// Get analysis data by program hash
export async function getAnalysis(hash: string) {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}`);
  if (!res.ok) return null;
  return res.json();
}

// Export report as HTML — returns the URL to open
export function getExportHtmlUrl(hash: string): string {
  const token = getStoredToken();
  const sep = '?';
  return `${API_BASE}/api/analysis/${hash}/export/html${token ? sep + 'token=' + encodeURIComponent(token) : ''}`;
}

// Export report as text — returns the URL to open
export function getExportTextUrl(hash: string): string {
  const token = getStoredToken();
  return `${API_BASE}/api/analysis/${hash}/export/text${token ? '?token=' + encodeURIComponent(token) : ''}`;
}

// Export report as PDF — returns the URL to download
export function getExportPdfUrl(hash: string): string {
  const token = getStoredToken();
  return `${API_BASE}/api/analysis/${hash}/export/pdf${token ? '?token=' + encodeURIComponent(token) : ''}`;
}

export async function getAnalyzers(hash: string) {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/analyzers`);
  if (!res.ok) return [];
  return res.json();
}

export async function getFiles(hash: string) {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/files`);
  if (!res.ok) return null;
  return res.json();
}

export async function getFileContent(hash: string, fileId: string) {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/files/${fileId}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getReports(hash: string) {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/reports`);
  if (!res.ok) return [];
  return res.json();
}

export async function getReportContent(hash: string, reportId: string) {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/reports/${reportId}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getGhidraResults(hash: string): Promise<AnalyzerRawResults | null> {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/results/ghidra`);
  if (!res.ok) return null;
  return res.json();
}

export async function getRadare2Results(hash: string): Promise<AnalyzerRawResults | null> {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/results/radare2`);
  if (!res.ok) return null;
  return res.json();
}

export async function getQilingResults(hash: string): Promise<AnalyzerRawResults | null> {
  const res = await authFetch(`${API_BASE}/api/analysis/${hash}/results/qiling`);
  if (!res.ok) return null;
  return res.json();
}

export async function getModels() {
  const res = await authFetch(`${API_BASE}/api/models`);
  if (!res.ok) return [];
  return res.json();
}

// WebSocket connection for real-time events
export function connectStream(sessionId: string, onEvent: (event: unknown) => void): WebSocket {
  const token = getStoredToken();
  const wsUrl = token
    ? `${WS_BASE}/${sessionId}?token=${encodeURIComponent(token)}`
    : `${WS_BASE}/${sessionId}`;
  const ws = new WebSocket(wsUrl);
  ws.onmessage = (e) => {
    try {
      onEvent(JSON.parse(e.data));
    } catch (err) {
      console.debug('Failed to parse stream event', err);
    }
  };
  return ws;
}

// Poll status until completed or error, with callback on each poll
export async function pollStatus(
  sessionId: string,
  onUpdate: (status: StatusResponse) => void,
  intervalMs = 2000,
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

// ---------------------------------------------------------------------------
// History / Past Analysis API
// ---------------------------------------------------------------------------

export interface HistoryItem {
  id: string;
  program_hash: string;
  binary_path: string;
  status: string;
  verdict: string | null;
  threat_score: number | null;
  summary: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  created_at: string;
  updated_at: string;
}

export interface HistoryListResponse {
  items: HistoryItem[];
  total: number;
  limit: number;
  offset: number;
}

export async function getHistory(
  limit = 50,
  offset = 0,
  status = '',
  search = '',
): Promise<HistoryListResponse> {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  params.set('offset', String(offset));
  if (status) params.set('status', status);
  if (search) params.set('search', search);
  const res = await authFetch(`${API_BASE}/api/history?${params}`);
  if (!res.ok) return { items: [], total: 0, limit, offset };
  return res.json();
}

export async function getHistoryItem(sessionId: string): Promise<HistoryItem | null> {
  const res = await authFetch(`${API_BASE}/api/history/${sessionId}`);
  if (!res.ok) return null;
  return res.json();
}

export async function restoreSession(sessionId: string): Promise<{ ok: boolean; session_id: string; program_hash: string; status: string } | null> {
  const res = await authFetch(`${API_BASE}/api/history/${sessionId}/restore`, { method: 'POST' });
  if (!res.ok) return null;
  return res.json();
}

export async function deleteHistoryItem(sessionId: string): Promise<boolean> {
  const res = await authFetch(`${API_BASE}/api/history/${sessionId}`, { method: 'DELETE' });
  return res.ok;
}
