# gireng - Backend Integration Guide

## Overview

This is a React-based cybersecurity analysis platform template. This guide explains all data structures, API endpoints needed, and how to integrate with your backend.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Data Types](#data-types)
3. [Pages & Components](#pages--components)
4. [API Endpoints Required](#api-endpoints-required)
5. [State Management](#state-management)
6. [WebSocket Integration](#websocket-integration)

---

## Project Structure

```
src/
├── components/
│   ├── analysis/          # Analysis view components
│   │   ├── AnalysisHeader.tsx
│   │   ├── AnalysisSection.tsx
│   │   ├── AnalysisTabs.tsx
│   │   ├── AnalyzerList.tsx
│   │   └── AnalyzerDetail.tsx
│   ├── chat/              # Chat interface components
│   │   ├── ChatInput.tsx
│   │   ├── ChatInterface.tsx
│   │   ├── CodeBlock.tsx
│   │   ├── MessageBubble.tsx
│   │   ├── ModelSelector.tsx
│   │   ├── QuickActionChips.tsx
│   │   ├── ToolCallCard.tsx
│   │   └── WelcomeScreen.tsx
│   ├── code/              # Code viewer components
│   │   └── CodeViewer.tsx
│   ├── data/              # Data display components
│   │   └── DataTable.tsx
│   ├── layout/            # Layout components
│   │   ├── MainLayout.tsx
│   │   ├── ResizablePanel.tsx
│   │   ├── Sidebar.tsx
│   │   └── TabbedPanel.tsx
│   ├── modals/            # Modal components
│   │   └── ShareModal.tsx
│   └── report/            # Report viewer components
│       └── ReportViewer.tsx
├── data/                  # Data layer (replace with API calls)
│   └── mockData.ts
├── types/                 # TypeScript type definitions
│   └── index.ts
├── App.tsx               # Main application component
└── index.css             # Global styles
```

---

## Data Types

### 1. Message

Chat message structure for the conversation.

```typescript
interface Message {
  id: string;                    // Unique message ID (UUID)
  content: string;               // Message content (Markdown supported)
  isUser: boolean;               // true = user message, false = AI response
  timestamp: Date;               // Message timestamp
  toolCalls?: ToolCall[];        // Optional: Tool calls made by AI
  codeBlocks?: CodeBlock[];      // Optional: Code blocks in message
  showAnalysisCompleted?: boolean; // Optional: Show analysis completion card
}
```

**Backend Response Example:**
```json
{
  "id": "msg-123",
  "content": "Analysis complete. Found 3 threats.",
  "isUser": false,
  "timestamp": "2026-01-28T10:30:00Z",
  "toolCalls": [
    {
      "id": "tool-1",
      "name": "virustotal_scan",
      "status": "completed",
      "progress": 7,
      "maxProgress": 7
    }
  ]
}
```

---

### 2. ToolCall

Represents a tool/agent call made during analysis.

```typescript
interface ToolCall {
  id: string;                    // Tool call ID
  name: string;                  // Tool name (displayed in UI)
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: any;                  // Tool result data
  progress?: number;             // Current progress
  maxProgress?: number;          // Total progress steps
}
```

---

### 3. CodeBlock

Code snippet displayed in chat.

```typescript
interface CodeBlock {
  id: string;                    // Block ID
  language: string;              // Programming language (python, c, javascript, etc.)
  filename?: string;             // Optional filename
  code: string;                  // Code content
}
```

---

### 4. AnalysisResult

Overall analysis result header information.

```typescript
interface AnalysisResult {
  hash: string;                  // File hash (SHA256)
  size: string;                  // File size (e.g., "49.34 KB")
  type: string;                  // File type (e.g., "ELF", "PE", "PDF")
  status: string;                // Analysis status (e.g., "COMPLETED")
  duration: string;              // Analysis duration (e.g., "2m 32s")
  started: string;               // Start timestamp
  completed: string;             // Completion timestamp
  verdict: string;               // Final verdict ("Malware", "Clean", "Suspicious")
  threatScore: number;           // Threat score (0-6)
  maxScore: number;              // Maximum possible score (6)
  tags: string[];                // Array of threat tags
}
```

**Backend Response Example:**
```json
{
  "hash": "abc123...",
  "size": "49.34 KB",
  "type": "ELF",
  "status": "COMPLETED",
  "duration": "2m 32s",
  "started": "2026-01-28T10:30:00Z",
  "completed": "2026-01-28T10:32:32Z",
  "verdict": "Malware",
  "threatScore": 3,
  "maxScore": 6,
  "tags": ["malware", "trojan", "backdoor", "linux"]
}
```

---

### 5. Analyzer

Individual analyzer/agent that processed the file.

```typescript
interface Analyzer {
  id: string;                    // Analyzer ID (ghidra, radare)
  name: string;                  // Display name
  source: string;                // Source system
  sourceUrl: string;             // Source URL
  verdict: 'Clean' | 'Malware' | 'Suspicious' | 'Not_extracted';
  details?: AnalyzerDetails;     // Detailed analysis results
}
```

**Supported Analyzers (Template configured for):**
- `ghidra` - Ghidra Reverse Engineer Agent
- `radare` - Radare Reverse Engineer Agent

**Backend Response Example:**
```json
{
  "id": "ghidra",
  "name": "Ghidra Reverse Engineer Agent",
  "source": "gireng",
  "sourceUrl": "https://github.com/danilchristianto/gireng",
  "verdict": "Malware",
  "details": {
    "executiveSummary": "Analysis found malicious PAM module...",
    "staticAnalysis": "Detailed static analysis...",
    "behavioralAnalysis": "Behavior observed...",
    "iocs": "Indicators of compromise...",
    "conclusion": "Final assessment...",
    "executionLogs": ["Log entry 1", "Log entry 2"]
  }
}
```

---

### 6. AnalyzerDetails

Detailed analysis from an analyzer.

```typescript
interface AnalyzerDetails {
  executiveSummary: string;      // Executive summary
  staticAnalysis: string;        // Static analysis findings
  behavioralAnalysis: string;    // Behavioral analysis
  iocs: string;                  // Indicators of compromise
  conclusion: string;            // Conclusion
  executionLogs: string[];       // Execution log entries
}
```

---

### 7. Model

AI model available for chat.

```typescript
interface Model {
  id: string;                    // Model ID
  name: string;                  // Display name
  icon: 'sparkle' | 'circle' | 'split';
  type: 'gemini' | 'gpt' | 'other';
  isSelected?: boolean;          // Currently selected
}
```

**Backend Response Example:**
```json
[
  {
    "id": "gemini-2.5-pro",
    "name": "Gemini 2.5 Pro",
    "icon": "sparkle",
    "type": "gemini",
    "isSelected": true
  },
  {
    "id": "claude-3-opus",
    "name": "Claude 3 Opus",
    "icon": "circle",
    "type": "other"
  }
]
```

---

### 8. Chat

Chat session/history item.

```typescript
interface Chat {
  id: string;                    // Chat ID
  title: string;                 // Chat title
  timestamp: Date;               // Last activity timestamp
  isActive?: boolean;            // Currently active chat
}
```

---

### 9. FileNode

File tree structure for analyzed files.

```typescript
interface FileNode {
  id: string;                    // Node ID
  name: string;                  // Filename
  type: 'file' | 'folder' | 'code';
  children?: FileNode[];         // Child nodes (for folders)
}
```

**Backend Response Example:**
```json
{
  "id": "root",
  "name": "abc123...",
  "type": "folder",
  "children": [
    {
      "id": "file1",
      "name": "decompiled.c",
      "type": "code"
    }
  ]
}
```

---

### 10. CodeFile

Decompiled/extracted code file content.

```typescript
interface CodeFile {
  id: string;                    // File ID
  name: string;                  // Filename
  language: string;              // Language for syntax highlighting
  content: string;               // File content
}
```

---

### 11. SimilarFile

Similar files found during analysis.

```typescript
interface SimilarFile {
  id: string;                    // File ID
  hash: string;                  // SHA256 hash
  labels: string[];              // Threat labels
}
```

**Backend Response Example:**
```json
[
  {
    "id": "sim1",
    "hash": "4aa28808483191c4247e97be2a73ae22a7fe54193e892aae23d7ca3280854df7",
    "labels": ["SSHDoor", "PamBack"]
  }
]
```

---

### 12. Analysis

Analysis summary for the resources panel.

```typescript
interface Analysis {
  id: string;                    // Analysis ID
  hash: string;                  // Full hash
  shortHash: string;             // Truncated hash for display
  tags: string[];                // Tags to display
  extraTagCount: number;         // Number of additional tags
  verdict: string;               // Verdict
  status: 'completed' | 'running' | 'pending';
}
```

---

### 13. Report

Generated report metadata.

```typescript
interface Report {
  id: string;                    // Report ID
  name: string;                  // Report filename
  timestamp: number;             // Unix timestamp
}
```

---

### 14. QuickAction

Quick action chips on welcome screen.

```typescript
interface QuickAction {
  id: string;                    // Action ID
  label: string;                 // Display label
  icon: string;                  // Lucide icon name
}
```

**Default Quick Actions:**
- CVEs Chart (BarChart3)
- Deobfuscate (Code2)
- Create Workflows (Workflow)
- APT Threat Report (Shield)
- Hash Research (Hash)

---

## Pages & Components

### 1. Welcome Screen (`/welcome`)

**Purpose:** Initial landing page when no chat is active.

**Data Required:**
- User name
- Available models list
- Quick actions

**API Endpoints:**
```
GET /api/models              # Fetch available AI models
GET /api/quick-actions       # Fetch quick action buttons
```

---

### 2. Chat Interface (`/chat`)

**Purpose:** Main chat conversation with AI.

**Data Required:**
- Messages array
- Current model ID
- Input placeholder text

**API Endpoints:**
```
GET /api/chats/:id/messages           # Fetch chat messages
POST /api/chats/:id/messages          # Send message
POST /api/chats/:id/messages/stream   # Stream AI response (SSE)
```

**WebSocket Events:**
```
message:received          # New message received
message:typing            # AI is typing
analysis:progress         # Analysis progress update
analysis:completed        # Analysis completed
```

---

### 3. Analysis View (`/analysis`)

**Purpose:** Detailed analysis results view.

**Data Required:**
- Analysis result header
- List of analyzers
- Similar files
- Analysis sections content

**API Endpoints:**
```
GET /api/analysis/:hash              # Get analysis summary
GET /api/analysis/:hash/analyzers    # Get all analyzer results
GET /api/analysis/:hash/similar      # Get similar files
```

---

### 4. Analyzer Detail View

**Purpose:** Detailed view for a specific analyzer (Ghidra/Radare).

**Data Required:**
- Analyzer details object

**API Endpoints:**
```
GET /api/analysis/:hash/analyzers/:analyzerId   # Get specific analyzer details
```

---

### 5. Code Viewer (Right Panel Tab)

**Purpose:** Display decompiled/extracted code files.

**Data Required:**
- File tree structure
- Code file content

**API Endpoints:**
```
GET /api/analysis/:hash/files          # Get file tree
GET /api/analysis/:hash/files/:fileId  # Get file content
```

---

### 6. Report Viewer (Right Panel Tab)

**Purpose:** Display generated analysis reports.

**Data Required:**
- Report list
- Report content (Markdown)

**API Endpoints:**
```
GET /api/analysis/:hash/reports        # Get report list
GET /api/analysis/:hash/reports/:id    # Get report content
```

---

## API Endpoints Required

### Authentication
```
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me
```

### Chats
```
GET    /api/chats              # List all chats
POST   /api/chats              # Create new chat
GET    /api/chats/:id          # Get chat details
DELETE /api/chats/:id          # Delete chat
GET    /api/chats/:id/messages # Get chat messages
POST   /api/chats/:id/messages # Send message
```

### Analysis
```
POST   /api/analysis           # Submit file for analysis
GET    /api/analysis/:hash     # Get analysis status
GET    /api/analysis/:hash/analyzers      # Get analyzer results
GET    /api/analysis/:hash/analyzers/:id  # Get specific analyzer
GET    /api/analysis/:hash/files          # Get analyzed files
GET    /api/analysis/:hash/files/:fileId  # Get file content
GET    /api/analysis/:hash/reports        # Get reports
GET    /api/analysis/:hash/reports/:id    # Get report content
GET    /api/analysis/:hash/similar        # Get similar files
```

### Models
```
GET /api/models                # Get available AI models
```

### Share
```
POST /api/share                # Generate share link
GET  /api/share/:token         # Get shared chat
```

---

## WebSocket Integration

### Connection
```javascript
const ws = new WebSocket('wss://your-api.com/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'your-jwt-token'
  }));
};
```

### Events to Handle

**Server → Client:**
```javascript
// Message received
{
  type: 'message',
  chatId: 'chat-123',
  message: Message
}

// Analysis progress
{
  type: 'analysis:progress',
  hash: 'abc123...',
  analyzer: 'ghidra',
  progress: 50,
  maxProgress: 100
}

// Analysis completed
{
  type: 'analysis:completed',
  hash: 'abc123...',
  result: AnalysisResult
}

// Tool call update
{
  type: 'tool:call',
  chatId: 'chat-123',
  toolCall: ToolCall
}
```

**Client → Server:**
```javascript
// Send message
{
  type: 'message:send',
  chatId: 'chat-123',
  content: 'Analyze this file'
}

// Subscribe to analysis
{
  type: 'analysis:subscribe',
  hash: 'abc123...'
}
```

---

## State Management

### Recommended: Zustand or Redux

```typescript
// store/chatStore.ts
import { create } from 'zustand';

interface ChatState {
  messages: Message[];
  currentChatId: string | null;
  selectedModel: Model;
  isLoading: boolean;
  
  // Actions
  sendMessage: (content: string) => Promise<void>;
  loadMessages: (chatId: string) => Promise<void>;
  setModel: (model: Model) => void;
}

export const useChatStore = create<ChatState>((set, get) => ({
  messages: [],
  currentChatId: null,
  selectedModel: defaultModel,
  isLoading: false,
  
  sendMessage: async (content: string) => {
    set({ isLoading: true });
    // API call to send message
    const response = await fetch('/api/chats/' + get().currentChatId + '/messages', {
      method: 'POST',
      body: JSON.stringify({ content, model: get().selectedModel.id })
    });
    const message = await response.json();
    set(state => ({ 
      messages: [...state.messages, message],
      isLoading: false 
    }));
  },
  
  loadMessages: async (chatId: string) => {
    const response = await fetch('/api/chats/' + chatId + '/messages');
    const messages = await response.json();
    set({ messages, currentChatId: chatId });
  },
  
  setModel: (model: Model) => set({ selectedModel: model })
}));
```

---

## Environment Variables

```bash
# .env
VITE_API_BASE_URL=https://api.yourdomain.com
VITE_WS_URL=wss://api.yourdomain.com/ws
VITE_APP_NAME=gireng
```

---

## Integration Checklist

- [ ] Set up API base URL in environment variables
- [ ] Implement authentication (JWT tokens)
- [ ] Create API client (axios/fetch wrapper)
- [ ] Implement WebSocket connection
- [ ] Replace mock data with API calls
- [ ] Add loading states
- [ ] Add error handling
- [ ] Implement file upload for analysis
- [ ] Set up SSE for streaming responses
- [ ] Test all analyzer integrations (Ghidra, Radare)

---

## Notes

1. **Analyzers:** Template is configured for Ghidra and Radare only. Remove other analyzers from backend responses.

2. **File Upload:** Add file upload component to chat input for malware submission.

3. **Streaming:** Use Server-Sent Events (SSE) or WebSocket for streaming AI responses.

4. **Progress:** Analysis progress should be pushed via WebSocket for real-time updates.

5. **Security:** All file hashes and analysis results should be validated on backend.
