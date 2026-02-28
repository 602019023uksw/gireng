# Backend Integration Guide

Complete reference for integrating the gireng frontend with the backend API. This guide covers all data types, API endpoints, component mapping, and real-time communication.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [API Configuration](#api-configuration)
3. [Data Types](#data-types)
4. [API Client Functions](#api-client-functions)
5. [API Endpoints](#api-endpoints)
6. [WebSocket Integration](#websocket-integration)
7. [Component–Endpoint Mapping](#componentendpoint-mapping)
8. [Application Flow](#application-flow)
9. [State Management](#state-management)
10. [Component Inventory](#component-inventory)
11. [Environment Variables](#environment-variables)

---

## Architecture Overview

The frontend is a state-driven single-page application (no router) built with React 19 + TypeScript. It communicates with the FastAPI backend through REST endpoints and WebSocket streaming.

```
┌─────────────────────────────────────────────────────┐
│  Frontend (React 19 / Vite 7 / TypeScript 5.9)      │
│                                                      │
│  src/lib/api.ts  ←→  Backend (FastAPI :8080)         │
│     REST   : POST /analyze, GET /status, POST /query │
│     WS     : /stream/{session_id}                    │
│     Export : /api/analysis/{hash}/export/{format}     │
│     History: /api/history/*                           │
│     Search : /api/query/*, /api/binary/*              │
└─────────────────────────────────────────────────────┘
```

### Layout Structure

```
<MainLayout>
  ├─ <Sidebar>               Left: new chat, session history/restore
  ├─ <header>                 Top: back button, model selector, panel toggle
  ├─ Main content area        AnimatePresence switching between views
  │   ├─ WelcomeScreen        File upload, quick actions, model selector
  │   ├─ ChatInterface        Message list + input, drag-and-drop upload
  │   └─ Analysis view
  │       ├─ AnalysisHeader
  │       ├─ AnalysisTabs     overview | analyzers | callgraph
  │       ├─ Overview          SimilarFiles table + AnalysisSummary (MarkdownContent)
  │       ├─ Analyzers         AnalyzerList
  │       └─ CallGraph         CallGraphView
  └─ <ResizablePanel>        Right: TabbedPanel with resources/code/report tabs
```

---

## API Configuration

All API communication flows through `src/lib/api.ts`.

```typescript
// Base URLs (from environment or defaults)
const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';
const WS_BASE  = import.meta.env.VITE_WS_URL || 'ws://localhost:8080/stream';
```

---

## Data Types

All types are defined in `src/types/index.ts`.

### 1. Message

Chat message between user and AI agent.

```typescript
interface Message {
  id: string;
  content: string;
  isUser: boolean;
  timestamp: Date;
  toolCalls?: ToolCall[];
  codeBlocks?: CodeBlock[];
  showAnalysisCompleted?: boolean;
  analysisHash?: string;
  analyzerCount?: number;
  analyzerTotal?: number;
  agentId?: string;
  agentName?: string;
}
```

### 2. ToolCall

Tool invocation status during analysis (Ghidra scripts, Radare2 commands).

```typescript
interface ToolCall {
  id: string;
  name: string;                  // e.g. "list_functions", "decompile_function"
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: string;
  progress?: number;
  maxProgress?: number;
}
```

### 3. CodeBlock

Code snippet embedded in a message.

```typescript
interface CodeBlock {
  id: string;
  language: string;              // Syntax highlighting language
  filename?: string;
  code: string;
}
```

### 4. AnalysisResult

Top-level analysis outcome for a binary.

```typescript
interface AnalysisResult {
  hash: string;
  size: number;
  type: string;
  status: string;
  duration: number;
  started: string;
  completed: string;
  verdict: string;
  threatScore: number;
  maxScore: number;
  tags: string[];
}
```

### 5. Analyzer

Individual analyzer result (Ghidra or Radare2).

```typescript
interface Analyzer {
  id: string;
  name: string;
  source: string;
  sourceUrl: string;
  verdict: 'Clean' | 'Malware' | 'Suspicious' | 'Not_extracted';
  details?: AnalyzerDetails;
}
```

### 6. AnalyzerDetails

Detailed findings from an analyzer.

```typescript
interface AnalyzerDetails {
  executiveSummary: string;
  staticAnalysis: string;
  behavioralAnalysis: string;
  iocs: string;
  conclusion: string;
  executionLogs: string[];
}
```

### 7. Agent

AI agent configuration for specialized analysis tasks.

```typescript
interface Agent {
  id: string;
  name: string;
  description: string;
  icon: string;
  prompt: string;
  capabilities: string[];
  exampleQueries: string[];
}
```

### 8. AgentMention

Reference to an agent within a message.

```typescript
interface AgentMention {
  agentId: string;
  agentName: string;
  startIndex: number;
  endIndex: number;
}
```

### 9. Model

Available LLM model.

```typescript
interface Model {
  id: string;
  name: string;
  icon: 'sparkle' | 'circle' | 'split';
  type: 'gemini' | 'gpt' | 'other';
  isSelected?: boolean;
}
```

### 10. Other Types

```typescript
interface Chat {
  id: string;
  title: string;
  timestamp: Date;
  isActive?: boolean;
}

interface FileNode {
  id: string;
  name: string;
  type: 'file' | 'folder' | 'code';
  children?: FileNode[];
}

interface CodeFile {
  id: string;
  name: string;
  language: string;
  content: string;
}

interface SimilarFile {
  id: string;
  hash: string;
  labels: string[];
}

interface Analysis {
  id: string;
  hash: string;
  shortHash: string;
  tags: string[];
  extraTagCount: number;
  verdict: string;
  status: 'completed' | 'running' | 'pending';
}

interface Report {
  id: string;
  name: string;
  timestamp: number;
  content?: string;
}

interface QuickAction {
  id: string;
  label: string;
  icon: string;                  // Lucide icon name
}

interface NavItem {
  id: string;
  icon: string;
  label: string;
  isActive?: boolean;
  hasNotification?: boolean;
}
```

### API-Specific Types (defined in `api.ts`)

```typescript
interface UploadResponse {
  session_id: string;
}

interface StatusResponse {
  session_id: string;
  status: string;
  state: any;
}

interface QueryResponse {
  ok: boolean;
  answer?: string;
  error?: string;
}

interface CallGraphRaw {
  ok?: boolean;
  nodes: any[];
  edges: any[];
  entry_points: string[];
}

interface CallGraphAnalysis {
  ok?: boolean;
  entries: any[];
  adjacency: AdjacencyRow[];
  chains: AttackChain[];
  cycles: any[];
  stats?: any;
}

interface AttackChain {
  category: string;
  sink: string;
  path: string[];
  description?: string;
}

interface AnalyzerRawResults {
  analyzer: string;
  binary?: any;
  functions?: any;
  strings?: any;
  call_graph?: CallGraphRaw;
  call_graph_analysis?: CallGraphAnalysis;
  decompiled?: any;
}

interface HistoryItem {
  id: string;
  program_hash: string;
  binary_path: string;
  status: string;
  verdict: string;
  threat_score: number;
  summary: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  created_at: string;
  updated_at: string;
}

interface HistoryListResponse {
  items: HistoryItem[];
  total: number;
  limit: number;
  offset: number;
}
```

---

## API Client Functions

All functions are in `src/lib/api.ts`:

| Function | Method | Endpoint | Description |
|----------|--------|----------|-------------|
| `uploadBinary(file)` | POST | `/analyze/upload` | Upload binary for analysis |
| `analyzePath(binaryPath)` | POST | `/analyze` | Analyze binary by server path |
| `getStatus(sessionId)` | GET | `/status/{id}` | Get session status and state |
| `sendQuery(sessionId, query)` | POST | `/query` | Follow-up question on session |
| `getAnalysis(hash)` | GET | `/api/analysis/{hash}` | Analysis metadata |
| `getAnalyzers(hash)` | GET | `/api/analysis/{hash}/analyzers` | Analyzer results list |
| `getFiles(hash)` | GET | `/api/analysis/{hash}/files` | File tree |
| `getFileContent(hash, fileId)` | GET | `/api/analysis/{hash}/files/{id}` | File code content |
| `getReports(hash)` | GET | `/api/analysis/{hash}/reports` | Report list |
| `getReportContent(hash, reportId)` | GET | `/api/analysis/{hash}/reports/{id}` | Report content |
| `getGhidraResults(hash)` | GET | `/api/analysis/{hash}/results/ghidra` | Raw Ghidra results |
| `getRadare2Results(hash)` | GET | `/api/analysis/{hash}/results/radare2` | Raw Radare2 results |
| `getExportHtmlUrl(hash)` | — | `/api/analysis/{hash}/export/html` | HTML export URL |
| `getExportTextUrl(hash)` | — | `/api/analysis/{hash}/export/text` | Text export URL |
| `getExportPdfUrl(hash)` | — | `/api/analysis/{hash}/export/pdf` | PDF export URL |
| `getModels()` | GET | `/api/models` | Available LLM models |
| `getHistory(limit, offset, status, search)` | GET | `/api/history` | List past analyses |
| `getHistoryItem(sessionId)` | GET | `/api/history/{id}` | Single history record |
| `restoreSession(sessionId)` | POST | `/api/history/{id}/restore` | Restore into memory |
| `deleteHistoryItem(sessionId)` | DELETE | `/api/history/{id}` | Delete analysis |
| `connectStream(sessionId, onEvent)` | WS | `/stream/{id}` | Real-time event stream |
| `pollStatus(sessionId, onUpdate, interval, maxPolls)` | — | Polling wrapper | Poll `getStatus` in loop |

---

## API Endpoints

### Core Operations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check, returns session count |
| POST | `/analyze` | Start analysis by server-side binary path |
| POST | `/analyze/upload` | Upload binary file (multipart) |
| GET | `/status/{session_id}` | Session status and full state |
| POST | `/query` | Follow-up natural-language query |
| POST | `/write_mode` | Toggle write mode for a session |
| POST | `/write_mode/confirm` | Confirm/approve write mode action |
| WS | `/stream/{session_id}` | WebSocket for real-time events |

### Analysis Data (by program hash)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/analysis/{hash}` | Analysis metadata |
| GET | `/api/analysis/{hash}/analyzers` | Analyzer list (Ghidra + Radare2) |
| GET | `/api/analysis/{hash}/analyzers/{id}` | Single analyzer detail |
| GET | `/api/analysis/{hash}/files` | File tree |
| GET | `/api/analysis/{hash}/files/{file_id}` | File content |
| GET | `/api/analysis/{hash}/reports` | Report list |
| GET | `/api/analysis/{hash}/reports/{id}` | Report content |
| GET | `/api/analysis/{hash}/similar` | Similar files |
| GET | `/api/analysis/{hash}/results/ghidra` | Raw Ghidra results |
| GET | `/api/analysis/{hash}/results/radare2` | Raw Radare2 results |

### Report Export (by program hash)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/analysis/{hash}/export/html` | HTML report (dark-themed, standalone) |
| GET | `/api/analysis/{hash}/export/text` | Plain-text report |
| GET | `/api/analysis/{hash}/export/pdf` | PDF report (white template, Playwright) |

### Report Export (by session ID)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/export/session/{id}/html` | HTML report by session |
| GET | `/export/session/{id}/agent/{agent}` | Per-agent HTML report |
| GET | `/export/session/{id}/text` | Text report by session |
| GET | `/export/session/{id}/pdf` | PDF report by session |

### History

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/history` | List analyses (`limit`, `offset`, `status`, `search`) |
| GET | `/api/history/{session_id}` | Single analysis summary |
| GET | `/api/history/{session_id}/qa` | Q&A history for session |
| POST | `/api/history/{session_id}/restore` | Restore session into memory |
| DELETE | `/api/history/{session_id}` | Delete analysis record |

### Cross-Binary Search

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/query/functions` | Search functions across binaries (`name`, `analyzer`, `limit`) |
| GET | `/api/query/strings` | Full-text string search (`pattern`, `limit`) |
| GET | `/api/query/iocs` | Search IOCs (`ioc_type`, `value`, `limit`) |

### Per-Binary Data

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/binary/{hash}/functions` | Functions for a binary |
| GET | `/api/binary/{hash}/decompilations` | Decompiled functions |
| GET | `/api/binary/{hash}/iocs` | IOCs for a binary |
| GET | `/api/binary/{hash}/attack-chains` | Attack chains |

### Models

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/models` | Available LLM models |

**Total: 38 endpoints**

---

## WebSocket Integration

### Connection

```typescript
import { connectStream } from '@/lib/api';

connectStream(sessionId, (event) => {
  switch (event.type) {
    case 'analysis:progress':
      // { status, step, progress }
      break;
    case 'analysis:completed':
      // Analysis finished — fetch full results
      break;
    case 'analysis:error':
      // { error }
      break;
    case 'message:typing':
      // Agent is processing
      break;
  }
});
```

### Event Types

| Event | Direction | Payload | Description |
|-------|-----------|---------|-------------|
| `analysis:progress` | Server → Client | `{ status, step, progress }` | Step-by-step analysis updates |
| `analysis:completed` | Server → Client | — | Analysis finished |
| `analysis:error` | Server → Client | `{ error }` | Analysis failed |
| `message:typing` | Server → Client | — | Agent started processing |

---

## Component–Endpoint Mapping

### WelcomeScreen

| Data Needed | API Call |
|-------------|----------|
| Available models | `getModels()` |
| File upload | `uploadBinary(file)` → `pollStatus()` |
| Path analysis | `analyzePath(path)` → `pollStatus()` |

### ChatInterface

| Data Needed | API Call |
|-------------|----------|
| Send message | `sendQuery(sessionId, query)` |
| Analysis progress | `connectStream(sessionId, onEvent)` |
| Agent mention | Resolved client-side from agent definitions |

### Analysis View (Overview Tab)

| Data Needed | API Call |
|-------------|----------|
| Analysis header | `getAnalysis(hash)` |
| Analyzer list | `getAnalyzers(hash)` |
| Similar files | Included in analysis state |
| Summary content | From `getGhidraResults(hash)` / `getRadare2Results(hash)` |

### Analysis View (Analyzers Tab)

| Data Needed | API Call |
|-------------|----------|
| Analyzer details | `getAnalyzers(hash)` (includes details) |
| Ghidra raw data | `getGhidraResults(hash)` |
| Radare2 raw data | `getRadare2Results(hash)` |

### Analysis View (Call Graph Tab)

| Data Needed | API Call |
|-------------|----------|
| Graph nodes/edges | `getGhidraResults(hash)` → `call_graph` field |
| Graph analysis | `getGhidraResults(hash)` → `call_graph_analysis` field |
| Attack chains | `getGhidraResults(hash)` → `call_graph_analysis.chains` |

### Right Panel — Code Tab

| Data Needed | API Call |
|-------------|----------|
| File tree | `getFiles(hash)` |
| File content | `getFileContent(hash, fileId)` |

### Right Panel — Report Tab

| Data Needed | API Call |
|-------------|----------|
| Report list | `getReports(hash)` |
| Report content | `getReportContent(hash, reportId)` |
| Export HTML | `getExportHtmlUrl(hash)` (opens in new tab) |
| Export PDF | `getExportPdfUrl(hash)` (opens in new tab) |
| Export text | `getExportTextUrl(hash)` (opens in new tab) |

### Sidebar

| Data Needed | API Call |
|-------------|----------|
| Session history | `getHistory(limit, offset)` |
| Restore session | `restoreSession(sessionId)` |
| Delete session | `deleteHistoryItem(sessionId)` |

---

## Application Flow

### 1. Binary Upload → Analysis

```
User drops/selects file
  → uploadBinary(file)
  → Receives { session_id }
  → connectStream(session_id) for real-time events
  → pollStatus(session_id) as fallback
  → On "analysis:completed" or status === "completed":
       fetchAnalysisData(hash)  (parallel fetch of all data)
  → Switch to analysis view
```

### 2. Follow-up Query

```
User types question in chat
  → sendQuery(session_id, query)
  → Receives { ok, answer }
  → Append message to messages array
  → Refresh side panel data if needed
```

### 3. Session Restore

```
User clicks session in sidebar
  → restoreSession(session_id)
  → Set session reference { id, hash }
  → fetchAnalysisData(hash)
  → Switch to analysis view
```

### 4. Report Export

```
User clicks export button or types report command
  → Regex detects report intent in chat
  → Opens getExportHtmlUrl(hash) / getExportPdfUrl(hash) in new tab
  → Backend generates standalone HTML/PDF and serves it
```

### 5. Data Fetch (fetchAnalysisData)

All fetched in parallel after analysis completes:

```typescript
// Parallel data fetch
const [analysis, analyzers, files, reports, ghidraResults, radare2Results] =
  await Promise.all([
    getAnalysis(hash),
    getAnalyzers(hash),
    getFiles(hash),
    getReports(hash),
    getGhidraResults(hash),
    getRadare2Results(hash),
  ]);
```

---

## State Management

The application manages state directly in `App.tsx` using React hooks:

```typescript
// View state
viewState: 'welcome' | 'chat' | 'analysis'

// Session
sessionRef: { id: string; hash: string }

// Chat
messages: Message[]
selectedModelId: string

// Analysis data
currentAnalysis: AnalysisResult | null
analyzers: Analyzer[]
fileTree: FileNode[]
codeFiles: CodeFile[]
reports: Report[]
analyses: Analysis[]
activeReport: Report | null

// Call graph
callGraphPanels: any[]

// UI state
activeTab: 'overview' | 'analyzers' | 'callgraph'
rightPanelOpen: boolean
rightPanelTab: 'resources' | 'code' | 'report'
rightPanelWidth: number
```

---

## Component Inventory

### Layout (5 components)

| Component | Purpose |
|-----------|---------|
| `MainLayout` | Root layout wrapper |
| `Sidebar` | Left panel: new chat, session history |
| `ResizablePanel` | Draggable right panel |
| `TabbedPanel` | Tabbed container (resources, code, report) |
| `ResourcesPanel` | Resources tab content |

### Chat (11 components)

| Component | Purpose |
|-----------|---------|
| `ChatInterface` | Main chat conversation UI |
| `ChatInput` | Message input with file upload |
| `MessageBubble` | Individual message display |
| `WelcomeScreen` | Landing page with upload |
| `ModelSelector` | LLM model picker dropdown |
| `AgentPicker` | Agent selection in chat input |
| `AgentSelector` | Agent configuration panel |
| `AnalysisCompletedCard` | Inline card when analysis finishes |
| `ToolCallCard` | Tool invocation status card |
| `CodeBlock` | Syntax-highlighted code in messages |
| `QuickActionChips` | Quick action buttons on welcome |

### Analysis (9 components)

| Component | Purpose |
|-----------|---------|
| `AnalysisHeader` | Hash, verdict, threat score |
| `AnalysisTabs` | Tab switcher (overview/analyzers/callgraph) |
| `AnalysisSection` | Collapsible content section |
| `AnalyzerList` | List of analyzers |
| `AnalyzerItem` | Individual analyzer card |
| `CallGraphView` | Interactive call graph visualization |
| `CircularProgress` | Circular progress indicator |
| `StatusBadge` | Status indicator badge |
| `TagCloud` | Tag display component |

### Code (1 component)

| Component | Purpose |
|-----------|---------|
| `CodeViewer` | Decompiled code file viewer |

### Common (1 component)

| Component | Purpose |
|-----------|---------|
| `MarkdownContent` | Markdown rendering with syntax highlighting |

### Data (1 component)

| Component | Purpose |
|-----------|---------|
| `DataTable` | Generic data table |

### Modals (1 component)

| Component | Purpose |
|-----------|---------|
| `ShareModal` | Share/export dialog |

### UI Primitives (~50 shadcn/ui components)

Reusable primitives in `components/ui/`: accordion, alert, badge, button, card, dialog, drawer, dropdown-menu, input, progress, scroll-area, select, separator, sheet, sidebar, skeleton, spinner, table, tabs, textarea, toggle, tooltip, and more.

---

## Environment Variables

```bash
# .env (frontend)
VITE_API_BASE_URL=http://localhost:8080    # Backend API base URL
VITE_WS_URL=ws://localhost:8080/stream     # WebSocket base URL
```

---

## Notes

1. **Analyzers**: The system supports two analyzers — Ghidra and Radare2. Both run in dedicated Docker containers and communicate through the backend agent.

2. **File Upload**: Drag-and-drop or click-to-upload in both the WelcomeScreen and ChatInterface. Files go to `/analyze/upload` as multipart form data.

3. **Streaming**: Real-time analysis progress uses WebSocket (`/stream/{session_id}`). The `pollStatus()` function serves as a fallback when WebSocket is unavailable.

4. **Report Export**: Three formats available — HTML (dark-themed standalone), PDF (white professional template via Playwright/Chromium), and plain text. Export URLs open in a new browser tab.

5. **History & Persistence**: Completed analyses are persisted to PostgreSQL. The sidebar lists past sessions via `/api/history`, and any session can be restored into memory.

6. **Call Graph**: Interactive graph visualization using raw call graph data from Ghidra. Includes attack chain detection, cycle analysis, and function adjacency data.

7. **Cross-Binary Search**: The `/api/query/*` and `/api/binary/*` endpoints enable searching across all analyzed binaries for functions, strings, IOCs, and attack chains.
