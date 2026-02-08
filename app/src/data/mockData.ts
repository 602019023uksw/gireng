// Template Data - Replace with API calls
// This file contains placeholder data structures for the IrengSec template
// All values should be replaced with actual data from your backend API

import type { 
  Message, 
  AnalysisResult, 
  Analyzer, 
  Model, 
  QuickAction, 
  Chat, 
  FileNode, 
  Analysis, 
  Report,
  NavItem,
  CodeFile,
  SimilarFile
} from '@/types';

// ============================================================================
// CHAT HISTORY
// ============================================================================
// API: GET /api/chats
// Description: List of user's chat sessions

export const mockChats: Chat[] = [
  // Template: Add chat sessions here
  // {
  //   id: 'chat-id',
  //   title: 'Chat Title',
  //   timestamp: new Date(),
  //   isActive: true,
  // }
];

// ============================================================================
// NAVIGATION ITEMS
// ============================================================================
// Description: Sidebar navigation items (static configuration)

export const mockNavItems: NavItem[] = [
  { id: 'history', icon: 'Clock', label: 'History' },
  { id: 'plugins', icon: 'Plug', label: 'Plugins' },
  { id: 'files', icon: 'FileText', label: 'Files' },
  { id: 'calendar', icon: 'Calendar', label: 'Calendar' },
];

// ============================================================================
// AI MODELS
// ============================================================================
// API: GET /api/models
// Description: Available AI models for chat

export const mockModels: Model[] = [
  {
    id: 'gemini-2.5-pro',
    name: 'Gemini 2.5 Pro',
    icon: 'sparkle',
    type: 'gemini',
    isSelected: true,
  },
  {
    id: 'gemini-2.5-flash',
    name: 'Gemini 2.5 Flash',
    icon: 'sparkle',
    type: 'gemini',
  },
  {
    id: 'claude-3-opus',
    name: 'Claude 3 Opus',
    icon: 'circle',
    type: 'other',
  },
  {
    id: 'claude-3-sonnet',
    name: 'Claude 3.5 Sonnet',
    icon: 'circle',
    type: 'other',
  },
  {
    id: 'gpt-4o',
    name: 'GPT-4o',
    icon: 'circle',
    type: 'gpt',
  },
  {
    id: 'gpt-4o-mini',
    name: 'GPT-4o Mini',
    icon: 'circle',
    type: 'gpt',
  },
];

// ============================================================================
// QUICK ACTIONS
// ============================================================================
// API: GET /api/quick-actions (optional - can be static)
// Description: Quick action buttons on welcome screen

export const mockQuickActions: QuickAction[] = [
  { id: 'cves', label: 'CVEs Chart', icon: 'BarChart3' },
  { id: 'deobfuscate', label: 'Deobfuscate', icon: 'Code2' },
  { id: 'workflows', label: 'Create Workflows', icon: 'Workflow' },
  { id: 'apt', label: 'APT Threat Report', icon: 'Shield' },
  { id: 'hash', label: 'Hash Research', icon: 'Hash' },
];

// ============================================================================
// CHAT MESSAGES
// ============================================================================
// API: GET /api/chats/:id/messages
// Description: Messages in current chat session

export const mockMessages: Message[] = [
  // Template: Messages will be populated from API
];

// ============================================================================
// ANALYSIS RESULT HEADER
// ============================================================================
// API: GET /api/analysis/:hash
// Description: Summary of analysis results

export const mockAnalysisResult: AnalysisResult = {
  hash: '',
  size: '',
  type: '',
  status: 'COMPLETED',
  duration: '',
  started: '',
  completed: '',
  verdict: '',
  threatScore: 0,
  maxScore: 6,
  tags: [],
};

// ============================================================================
// ANALYZERS
// ============================================================================
// API: GET /api/analysis/:hash/analyzers
// Description: Results from each analyzer (Ghidra and Radare only)
// Note: Template is configured for Ghidra and Radare only

export const mockAnalyzers: Analyzer[] = [
  {
    id: 'ghidra',
    name: 'Ghidra Reverse Engineer Agent',
    source: 'Ireng',
    sourceUrl: 'https://irengsec.ai',
    verdict: 'Clean',
    details: {
      executiveSummary: '',
      staticAnalysis: '',
      behavioralAnalysis: '',
      iocs: '',
      conclusion: '',
      executionLogs: [],
    },
  },
  {
    id: 'radare',
    name: 'Radare Reverse Engineer Agent',
    source: 'Ireng',
    sourceUrl: 'https://irengsec.ai',
    verdict: 'Clean',
    details: {
      executiveSummary: '',
      staticAnalysis: '',
      behavioralAnalysis: '',
      iocs: '',
      conclusion: '',
      executionLogs: [],
    },
  },
];

// ============================================================================
// ANALYZED FILES TREE
// ============================================================================
// API: GET /api/analysis/:hash/files
// Description: File tree structure of analyzed files

export const mockAnalyzedFiles: FileNode[] = [
  // Template: File tree will be populated from API
  // {
  //   id: 'root',
  //   name: 'hash-value',
  //   type: 'folder',
  //   children: [
  //     { id: 'file1', name: 'decompiled.c', type: 'code' },
  //   ],
  // }
];

// ============================================================================
// CODE FILES
// ============================================================================
// API: GET /api/analysis/:hash/files/:fileId
// Description: Decompiled/extracted code file content

export const mockCodeFiles: CodeFile[] = [
  // Template: Code files will be populated from API
  // {
  //   id: 'file1',
  //   name: 'decompiled.c',
  //   language: 'c',
  //   content: '// Code content here',
  // }
];

// ============================================================================
// SIMILAR FILES
// ============================================================================
// API: GET /api/analysis/:hash/similar
// Description: Similar files found during analysis

export const mockSimilarFiles: SimilarFile[] = [
  // Template: Similar files will be populated from API
  // {
  //   id: 'sim1',
  //   hash: 'sha256-hash',
  //   labels: ['label1', 'label2'],
  // }
];

// ============================================================================
// ANALYSES SUMMARY
// ============================================================================
// API: GET /api/analysis/:hash/summary
// Description: Analysis summary for resources panel

export const mockAnalyses: Analysis[] = [
  // Template: Analyses will be populated from API
  // {
  //   id: 'analysis-1',
  //   hash: 'full-hash',
  //   shortHash: 'truncated-hash...',
  //   tags: ['tag1', 'tag2'],
  //   extraTagCount: 0,
  //   verdict: 'Malware',
  //   status: 'completed',
  // }
];

// ============================================================================
// REPORTS
// ============================================================================
// API: GET /api/analysis/:hash/reports
// Description: Generated analysis reports

export const mockReports: Report[] = [
  // Template: Reports will be populated from API
  // {
  //   id: 'report-1',
  //   name: 'report_1234567890.md',
  //   timestamp: 1234567890,
  // }
];

// ============================================================================
// REPORT CONTENT
// ============================================================================
// API: GET /api/analysis/:hash/reports/:id
// Description: Markdown content of analysis report

export const mockReportContent = '';
