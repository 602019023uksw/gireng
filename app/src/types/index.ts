export interface Message {
  id: string;
  content: string;
  isUser: boolean;
  timestamp: Date;
  toolCalls?: ToolCall[];
  codeBlocks?: CodeBlock[];
  showAnalysisCompleted?: boolean;
  analysisHash?: string;  // Hash of the analyzed binary
  analyzerCount?: number; // Number of completed analyzers
  analyzerTotal?: number; // Total number of analyzers
  agentId?: string;  // ID of the agent mentioned (@ghidra-analyzer)
  agentName?: string; // Display name of the agent
}

export interface CodeBlock {
  id: string;
  language: string;
  filename?: string;
  code: string;
}

export interface ToolCall {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: unknown;
  progress?: number;
  maxProgress?: number;
  etaSeconds?: number;
  phase?: string;
}

export interface AnalysisResult {
  hash: string;
  size: string;
  type: string;
  status: string;
  duration: string;
  started: string;
  completed: string;
  verdict: string;
  threatScore: number;
  maxScore: number;
  tags: string[];
  malwareType?: string;
  malwareTypeConfidence?: string;
}

export interface Analyzer {
  id: string;
  name: string;
  source: string;
  sourceUrl: string;
  verdict: 'Clean' | 'Malware' | 'Suspicious' | 'Not_extracted' | string;
  details?: AnalyzerDetails;
}

export interface AnalyzerDetails {
  executiveSummary: string;
  staticAnalysis: string;
  behavioralAnalysis: string;
  iocs: string;
  conclusion: string;
  executionLogs: string[];
}

export interface Model {
  id: string;
  name: string;
  icon: 'sparkle' | 'circle' | 'split';
  type: 'gemini' | 'gpt' | 'other';
  isSelected?: boolean;
}

export interface QuickAction {
  id: string;
  label: string;
  icon: string;
}

export interface Chat {
  id: string;
  title: string;
  timestamp: Date;
  isActive?: boolean;
}

export interface FileNode {
  id: string;
  name: string;
  type: 'file' | 'folder' | 'code';
  children?: FileNode[];
}

export interface CodeFile {
  id: string;
  name: string;
  language: string;
  content: string;
}

export interface SimilarFile {
  id: string;
  hash: string;
  labels: string[];
}

export interface Analysis {
  id: string;
  hash: string;
  shortHash: string;
  tags: string[];
  extraTagCount: number;
  verdict: string;
  status: 'completed' | 'running' | 'pending';
}

export interface Report {
  id: string;
  name: string;
  timestamp: number;
  content?: string;
}

export interface NavItem {
  id: string;
  icon: string;
  label: string;
  isActive?: boolean;
  hasNotification?: boolean;
}

// Agent Types for @mention functionality
export interface Agent {
  id: string;
  name: string;
  description: string;
  icon: string;
  prompt: string;
  capabilities: string[];
  exampleQueries: string[];
}

export interface AgentMention {
  agentId: string;
  agentName: string;
  startIndex: number;
  endIndex: number;
}
