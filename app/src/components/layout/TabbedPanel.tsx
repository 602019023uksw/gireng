import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { X, LayoutGrid, FileCode, FileText, FileCheck, Download, ChevronDown, Activity } from 'lucide-react';
import type { FileNode, Analysis, Report, CodeFile } from '@/types';
import { TagCloud } from '@/components/analysis/TagCloud';
import { ChevronRight, FolderOpen } from 'lucide-react';
import { AnimatePresence } from 'framer-motion';
import { MarkdownContent } from '@/components/common/MarkdownContent';
import { getExportHtmlUrl, getExportTextUrl, getExportPdfUrl } from '@/lib/api';
import type { AnalyzerRawResults } from '@/lib/api';
import { QilingResultsView } from '@/components/analysis/QilingResultsView';
import { HexViewer } from '@/components/code/HexViewer';
import { DisassemblyView } from '@/components/code/DisassemblyView';

interface TabbedPanelProps {
  files: FileNode[];
  analyses: Analysis[];
  reports: Report[];
  codeFiles: CodeFile[];
  activeTab: 'resources' | 'code' | 'report' | 'dynamic';
  activeCodeFileId?: string;
  activeReport?: Report | null;
  programHash?: string | null;
  qilingResults?: AnalyzerRawResults | null;
  codeViewMode?: 'decompiled' | 'disassembly' | 'hex';
  onTabChange: (tab: 'resources' | 'code' | 'report' | 'dynamic') => void;
  onCodeFileChange: (fileId: string) => void;
  onReportSelect?: (reportId: string) => void;
  onCodeViewModeChange?: (mode: 'decompiled' | 'disassembly' | 'hex') => void;
  onClose: () => void;
}

interface FileTreeItemProps {
  node: FileNode;
  level?: number;
  onFileClick?: (fileId: string) => void;
}

function FileTreeItem({ node, level = 0, onFileClick }: FileTreeItemProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const hasChildren = node.children && node.children.length > 0;

  const getIcon = () => {
    if (hasChildren) return <FolderOpen className="w-4 h-4 text-accent-blue" />;
    return <FileCode className="w-4 h-4 text-accent-green" />;
  };

  const handleClick = () => {
    if (hasChildren) {
      setIsExpanded(!isExpanded);
    } else if (onFileClick) {
      onFileClick(node.id);
    }
  };

  return (
    <div>
      <button
        onClick={handleClick}
        className="w-full flex items-center gap-2 py-1.5 text-left hover:bg-bg-hover rounded-lg transition-colors duration-150"
        style={{ paddingLeft: `${level * 16 + 8}px` }}
      >
        {hasChildren && (
          <motion.div
            animate={{ rotate: isExpanded ? 90 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronRight className="w-3 h-3 text-text-muted" />
          </motion.div>
        )}
        {!hasChildren && <span className="w-3" />}
        {getIcon()}
        <span className="text-sm text-text-primary truncate">{node.name}</span>
      </button>

      <AnimatePresence>
        {isExpanded && hasChildren && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            {node.children?.map((child) => (
              <FileTreeItem
                key={child.id}
                node={child}
                level={level + 1}
                onFileClick={onFileClick}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

interface SectionProps {
  title: string;
  icon: React.ElementType;
  count: number;
  children: React.ReactNode;
  defaultExpanded?: boolean;
}

function Section({ title, icon: Icon, count, children, defaultExpanded = true }: SectionProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  return (
    <div
      className="rounded-2xl overflow-hidden mb-3 bg-white"
      style={{
        border: '1px solid #e8eaed',
        boxShadow: '0 1px 2px rgba(60, 64, 67, 0.08)',
      }}
    >
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-bg-hover transition-colors duration-150"
      >
        <div className="flex items-center gap-3">
          <Icon className="w-5 h-5 text-text-secondary" />
          <span className="text-sm font-medium text-text-primary">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-muted">{count}</span>
          <motion.div
            animate={{ rotate: isExpanded ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronDown className="w-4 h-4 text-text-secondary" />
          </motion.div>
        </div>
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: 'auto' }}
            exit={{ height: 0 }}
            transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
            className="overflow-hidden"
          >
            <div className="p-4" style={{ background: '#f8fafd' }}>
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function ExportDropdown({ hash }: { hash: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const items = [
    { label: 'HTML Report', url: getExportHtmlUrl(hash) },
    { label: 'Text Report', url: getExportTextUrl(hash) },
    { label: 'PDF Report', url: getExportPdfUrl(hash) },
  ];

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-colors duration-150"
        style={{
          background: '#e8f0fe',
          color: '#1a73e8',
          border: '1px solid #d2e3fc',
        }}
        title="Export report"
      >
        <Download className="w-3.5 h-3.5" />
        Export
        <ChevronDown className={`w-3 h-3 transition-transform duration-150 ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          className="absolute right-0 mt-1 z-50 rounded-2xl shadow-xl overflow-hidden min-w-[160px]"
          style={{
            background: '#ffffff',
            border: '1px solid #e8eaed',
          }}
        >
          {items.map((item) => (
            <a
              key={item.label}
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-4 py-2.5 text-xs text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors duration-150"
            >
              <Download className="w-3.5 h-3.5" />
              {item.label}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

export function TabbedPanel({
  files,
  analyses,
  reports,
  codeFiles,
  activeTab,
  activeCodeFileId,
  activeReport,
  programHash,
  qilingResults,
  codeViewMode,
  onTabChange,
  onCodeFileChange,
  onReportSelect,
  onCodeViewModeChange,
  onClose,
}: TabbedPanelProps) {
  const activeCodeFile = codeFiles.find(f => f.id === activeCodeFileId) || codeFiles[0];

  const renderTabContent = () => {
    switch (activeTab) {
      case 'resources':
        return (
          <div className="p-4 overflow-y-auto scrollbar-dark h-full">
            {/* Analyzed Files */}
            <Section title="Analyzed Files" icon={FolderOpen} count={files.length}>
              {files.map((file) => (
                <FileTreeItem
                  key={file.id}
                  node={file}
                  onFileClick={(id) => {
                    onCodeFileChange(id);
                    onTabChange('code');
                  }}
                />
              ))}
            </Section>

            {/* Analyses */}
            <Section title="Analyses" icon={FileCheck} count={analyses.length}>
              {analyses.map((analysis) => (
                <div
                  key={analysis.id}
                  className="flex items-start gap-3 p-3 rounded-2xl hover:bg-bg-hover transition-colors duration-150"
                  style={{
                    background: '#ffffff',
                    border: '1px solid #e8eaed',
                  }}
                >
                  <div
                    className="w-10 h-10 rounded-2xl flex items-center justify-center flex-shrink-0"
                    style={{
                      background: '#f8fafd',
                      border: '1px solid #e8eaed',
                    }}
                  >
                    <FileText className="w-5 h-5 text-text-secondary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-text-primary truncate">
                      {analysis.shortHash}
                    </p>
                    <p className="text-xs text-text-muted truncate mt-0.5">
                      {analysis.hash}
                    </p>
                    <div className="mt-2">
                      <TagCloud tags={analysis.tags} maxVisible={6} />
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <p className="text-xs text-text-muted uppercase tracking-wider">Verdict</p>
                    <p className={`text-sm font-semibold ${
                      analysis.verdict === 'Malware' ? 'text-accent-red'
                      : analysis.verdict === 'Suspicious' ? 'text-accent-orange'
                      : 'text-accent-green'
                    }`}>
                      {analysis.verdict}
                    </p>
                  </div>
                </div>
              ))}
            </Section>

            {/* Reports */}
            <Section title="Reports" icon={FileText} count={reports.length}>
              {reports.map((report) => (
                <button
                  key={report.id}
                  onClick={() => {
                    if (onReportSelect) onReportSelect(report.id);
                    onTabChange('report');
                  }}
                  className="w-full flex items-center gap-3 p-3 hover:bg-bg-hover rounded-xl transition-colors duration-150 text-left"
                >
                  <FileText className="w-5 h-5 text-text-secondary" />
                  <span className="text-sm text-text-primary">{report.name}</span>
                </button>
              ))}
            </Section>
          </div>
        );

      case 'code':
        return (
          <div className="flex flex-col h-full">
            {/* View Mode Toggle */}
            <div className="flex items-center gap-1 px-3 py-2 border-b"
              style={{ borderColor: '#e8eaed' }}
            >
              {(['decompiled', 'disassembly', 'hex'] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => onCodeViewModeChange?.(mode)}
                  className={`px-3 py-1.5 rounded-full text-xs font-medium capitalize transition-all ${
                    (codeViewMode || 'decompiled') === mode
                      ? 'text-accent-blue bg-blue-50'
                      : 'text-text-muted hover:text-text-primary hover:bg-bg-hover'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>

            {/* Code File Tabs */}
            <div className="flex items-center gap-1 px-3 py-2 border-b overflow-x-auto scrollbar-hide"
              style={{ borderColor: '#e8eaed' }}
            >
              {codeFiles.map((file) => (
                <button
                  key={file.id}
                  onClick={() => onCodeFileChange(file.id)}
                  className={`px-3 py-1.5 rounded-full text-xs font-medium whitespace-nowrap transition-all duration-150 ${
                    file.id === activeCodeFileId
                      ? 'text-accent-blue'
                      : 'text-text-secondary hover:text-text-primary'
                  }`}
                  style={{
                    background: file.id === activeCodeFileId
                      ? '#e8f0fe'
                      : 'transparent',
                    border: file.id === activeCodeFileId
                      ? '1px solid #d2e3fc'
                      : '1px solid transparent',
                  }}
                >
                  {file.name}
                </button>
              ))}
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-auto scrollbar-dark">
              {(codeViewMode || 'decompiled') === 'hex' && activeCodeFile?.hexDump ? (
                <HexViewer lines={activeCodeFile.hexDump.lines} />
              ) : (codeViewMode || 'decompiled') === 'disassembly' && activeCodeFile?.disassembly ? (
                <DisassemblyView instructions={activeCodeFile.disassembly.instructions} />
              ) : (
                <div className="p-4">
                  <pre className="text-sm font-mono text-text-secondary">
                    {activeCodeFile?.content}
                  </pre>
                </div>
              )}
            </div>
          </div>
        );

      case 'report':
        return (
          <div className="flex flex-col h-full">
            <div className="flex-1 overflow-y-auto scrollbar-dark p-4">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-text-primary">
                  {activeReport?.name || 'Analysis Report'}
                </h3>
                {programHash && <ExportDropdown hash={programHash} />}
              </div>
              {activeReport?.content ? (
                <MarkdownContent content={activeReport.content} compact />
              ) : (
                <div className="text-sm text-text-muted italic">
                  Select a report from the Resources tab to view its content.
                </div>
              )}
            </div>
          </div>
        );

      case 'dynamic':
        return (
          <div className="flex flex-col h-full">
            <div className="flex-1 overflow-y-auto scrollbar-dark p-4">
              <h3 className="text-lg font-semibold text-text-primary mb-4">
                Qiling Dynamic Analysis
              </h3>
              {qilingResults ? (
                <QilingResultsView results={qilingResults} />
              ) : (
                <div className="text-sm text-text-muted italic">
                  No dynamic analysis data available.
                </div>
              )}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="h-full flex flex-col"
      style={{
        background: 'rgba(255, 255, 255, 0.96)',
      }}
    >
      {/* Header with Tabs */}
      <div className="flex items-center justify-between px-4 py-3 border-b"
        style={{ borderColor: '#e8eaed' }}
      >
        <div className="flex items-center gap-1">
          {/* Resources Tab */}
          <button
            onClick={() => onTabChange('resources')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-all duration-150 ${
              activeTab === 'resources'
                ? 'text-accent-blue'
                : 'text-text-secondary hover:text-text-primary'
            }`}
            style={{
              background: activeTab === 'resources'
                ? '#e8f0fe'
                : 'transparent',
            }}
          >
            <LayoutGrid className="w-4 h-4" />
            <span>Resources</span>
          </button>

          {/* Analysis Tab */}
          <button
            onClick={() => onTabChange('code')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-all duration-150 ${
              activeTab === 'code'
                ? 'text-accent-blue'
                : 'text-text-secondary hover:text-text-primary'
            }`}
            style={{
              background: activeTab === 'code'
                ? '#e8f0fe'
                : 'transparent',
            }}
          >
            <FileCode className="w-4 h-4" />
            <span>Analysis: ...</span>
            {activeCodeFile && (
              <span className="text-xs text-text-muted truncate max-w-[80px]">
                {activeCodeFile.name}
              </span>
            )}
          </button>

          {/* Dynamic Analysis Tab - only show if data exists */}
          {qilingResults && (
            <button
              onClick={() => onTabChange('dynamic')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-all duration-150 ${
                activeTab === 'dynamic'
                  ? 'text-accent-blue'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
              style={{
                background: activeTab === 'dynamic'
                  ? '#e8f0fe'
                  : 'transparent',
              }}
            >
              <Activity className="w-4 h-4" />
              <span>Dynamic</span>
            </button>
          )}
        </div>

        <button
          onClick={onClose}
          className="w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-accent-blue hover:bg-bg-hover transition-all duration-150"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-hidden">
        {renderTabContent()}
      </div>
    </div>
  );
}

export default TabbedPanel;
