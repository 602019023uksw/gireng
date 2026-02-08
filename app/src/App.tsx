import { useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Share, PanelRight, ArrowLeft } from 'lucide-react';

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
import { DataTable } from '@/components/data/DataTable';
import { ShareModal } from '@/components/modals/ShareModal';
import { ModelSelector } from '@/components/chat/ModelSelector';

import {
  uploadBinary,
  sendQuery,
  pollStatus,
  getAnalyzers,
  getFiles,
  getFileContent,
  getReports,
  getReportContent,
} from '@/lib/api';
import type { StatusResponse } from '@/lib/api';

import {
  mockChats,
  mockQuickActions,
  mockAnalysisResult,
  mockSimilarFiles,
} from '@/data/mockData';

import type { Message, Analyzer, FileNode, CodeFile, Report, Analysis } from '@/types';

type ViewState = 'welcome' | 'chat' | 'analysis';
type RightPanelTab = 'resources' | 'code' | 'report';

const currentUser = { name: '' };

function App() {
  const [viewState, setViewState] = useState<ViewState>('welcome');
  const [selectedModelId, setSelectedModelId] = useState('glm-4.7');
  const [messages, setMessages] = useState<Message[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'analyzers'>('overview');
  const [rightPanelOpen, setRightPanelOpen] = useState(true);
  const [rightPanelTab, setRightPanelTab] = useState<RightPanelTab>('resources');
  const [activeCodeFileId, setActiveCodeFileId] = useState<string>('');
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [rightPanelWidth, setRightPanelWidth] = useState(400);
  
  const [currentAnalysis, setCurrentAnalysis] = useState(mockAnalysisResult);
  const [analyzers, setAnalyzers] = useState<Analyzer[]>([]);
  const [fileTree, setFileTree] = useState<FileNode[]>([]);
  const [codeFiles, setCodeFiles] = useState<CodeFile[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [analyses, setAnalyses] = useState<Analysis[]>([]);

  // Track current session
  const sessionRef = useRef<{ id: string; hash: string } | null>(null);

  // Fetch all side-panel data for a completed analysis
  const fetchAnalysisData = useCallback(async (hash: string) => {
    try {
      const [analyzersData, filesData, reportsData] = await Promise.all([
        getAnalyzers(hash),
        getFiles(hash),
        getReports(hash),
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
      setAnalyses([{
        id: hash,
        hash,
        shortHash: hash.slice(0, 16) + '...',
        tags: ['ghidra'],
        extraTagCount: 0,
        verdict: analyzersData?.[0]?.verdict || 'Unknown',
        status: 'completed',
      }]);
    } catch (err) {
      console.error('Failed to fetch analysis data:', err);
    }
  }, []);

  // Handle file upload (drag-and-drop or file picker)
  const handleFileUpload = useCallback(async (file: File) => {
    const uploadMsg: Message = {
      id: Date.now().toString(),
      content: `Uploading binary: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`,
      isUser: true,
      timestamp: new Date(),
    };
    setMessages(prev => [...prev, uploadMsg]);
    setViewState('chat');

    try {
      const { session_id } = await uploadBinary(file);
      const analyzingMsg: Message = {
        id: (Date.now() + 1).toString(),
        content: `Binary uploaded. Ghidra is analyzing **${file.name}**... This may take 1-2 minutes.`,
        isUser: false,
        timestamp: new Date(),
        toolCalls: [{ id: '1', name: 'Ghidra Analysis', status: 'running' }],
      };
      setMessages(prev => [...prev, analyzingMsg]);

      // Poll until done
      const result = await pollStatus(session_id, (s) => {
        // Update the analyzing message with current status
      });

      const hash = result.state.program_hash;
      sessionRef.current = { id: session_id, hash };

      // Build result message
      const summary = result.state.summary || 'Analysis completed.';
      const funcCount = result.state.analysis_results?.functions?.functions?.length || 0;
      const strCount = result.state.analysis_results?.strings?.strings?.length || 0;

      const resultMsg: Message = {
        id: (Date.now() + 2).toString(),
        content: summary + `\n\n---\n**${funcCount}** functions, **${strCount}** strings found.`,
        isUser: false,
        timestamp: new Date(),
        toolCalls: [{ id: '1', name: 'Ghidra Analysis', status: 'completed' }],
        showAnalysisCompleted: true,
      };
      setMessages(prev => {
        // Replace the "analyzing" message with the result
        const filtered = prev.filter(m => m.id !== analyzingMsg.id);
        return [...filtered, resultMsg];
      });

      // Populate side panel data
      setCurrentAnalysis({
        ...mockAnalysisResult,
        hash,
        status: result.status.toUpperCase(),
        type: result.state.analysis_results?.binary?.architecture || 'Unknown',
        verdict: 'Suspicious',
      });
      await fetchAnalysisData(hash);
    } catch (err: any) {
      const errMsg: Message = {
        id: (Date.now() + 3).toString(),
        content: `Error: ${err.message}`,
        isUser: false,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errMsg]);
    }
  }, [fetchAnalysisData]);

  const handleSendMessage = useCallback(async (content: string, agentId?: string) => {
    const userMessage: Message = {
      id: Date.now().toString(),
      content,
      isUser: true,
      timestamp: new Date(),
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
      await sendQuery(sessionRef.current.id, content);
      const result = await pollStatus(sessionRef.current.id, () => {});

      const summary = result.state.summary || 'Analysis completed.';
      const responseMsg: Message = {
        id: (Date.now() + 2).toString(),
        content: summary,
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
    } catch (err: any) {
      const errMsg: Message = {
        id: (Date.now() + 3).toString(),
        content: `Error: ${err.message}`,
        isUser: false,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errMsg]);
    }
  }, [fetchAnalysisData]);

  const handleNewChat = () => {
    setMessages([]);
    sessionRef.current = null;
    setAnalyzers([]);
    setFileTree([]);
    setCodeFiles([]);
    setReports([]);
    setAnalyses([]);
    setViewState('welcome');
  };

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
          onTabChange={setRightPanelTab}
          onCodeFileChange={setActiveCodeFileId}
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
  const similarFilesRows = mockSimilarFiles.length > 0 
    ? mockSimilarFiles.map((file) => ({
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
            chats={mockChats}
            onNewChat={handleNewChat}
          />
        }
        rightPanel={renderRightPanel()}
      >
        {/* Top Header - Glass Terminal Style */}
        <header
          className="h-14 flex items-center justify-between px-4 flex-shrink-0 backdrop-blur-xl relative z-10"
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
            <button
              onClick={() => setShareModalOpen(true)}
              className="flex items-center gap-2 px-3 py-1.5 text-text-secondary hover:text-text-primary rounded-lg transition-all duration-150 hover:bg-white/5"
            >
              <Share className="w-4 h-4" />
              <span className="text-sm">Share</span>
            </button>
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
                  userName={currentUser.name}
                  selectedModelId={selectedModelId}
                  quickActions={mockQuickActions}
                  onModelSelect={setSelectedModelId}
                  onSendMessage={handleSendMessage}
                  onFileUpload={handleFileUpload}
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
                        {mockSimilarFiles.length > 0 && (
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

                        {/* Analysis Summary - Template: Populate from API */}
                        <AnalysisSection title="Analysis Summary">
                          <p className="text-sm text-text-secondary">
                            Analysis results will be displayed here. Connect to your backend API to populate this section.
                          </p>
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
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </MainLayout>

      {/* Share Modal */}
      <ShareModal
        isOpen={shareModalOpen}
        onClose={() => setShareModalOpen(false)}
        chatTitle="Analysis Session"
      />
    </div>
  );
}

export default App;
