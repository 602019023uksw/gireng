import { useState } from 'react';
import { motion } from 'framer-motion';
import { X, LayoutGrid, FileCode, FileText, FileCheck } from 'lucide-react';
import type { FileNode, Analysis, Report, CodeFile } from '@/types';
import { TagCloud } from '@/components/analysis/TagCloud';
import { ChevronRight, ChevronDown, FolderOpen } from 'lucide-react';
import { AnimatePresence } from 'framer-motion';

interface TabbedPanelProps {
  files: FileNode[];
  analyses: Analysis[];
  reports: Report[];
  codeFiles: CodeFile[];
  activeTab: 'resources' | 'code' | 'report';
  activeCodeFileId?: string;
  onTabChange: (tab: 'resources' | 'code' | 'report') => void;
  onCodeFileChange: (fileId: string) => void;
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
        className="w-full flex items-center gap-2 py-1.5 text-left hover:bg-white/5 rounded-md transition-colors duration-150"
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
      className="rounded-xl overflow-hidden mb-3"
      style={{
        background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.4) 0%, rgba(15, 20, 35, 0.25) 100%)',
        border: '1px solid rgba(100, 120, 180, 0.15)',
      }}
    >
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors duration-150"
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
            <div className="p-4" style={{ background: 'rgba(8, 10, 18, 0.4)' }}>
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
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
  onTabChange,
  onCodeFileChange,
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
                  className="flex items-start gap-3 p-3 rounded-xl hover:bg-white/5 transition-colors duration-150"
                  style={{
                    background: 'rgba(20, 28, 50, 0.4)',
                    border: '1px solid rgba(100, 120, 180, 0.15)',
                  }}
                >
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{
                      background: 'rgba(20, 28, 50, 0.6)',
                      border: '1px solid rgba(100, 120, 180, 0.2)',
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
                      analysis.verdict === 'Malware' ? 'text-accent-red' : 'text-accent-green'
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
                  onClick={() => onTabChange('report')}
                  className="w-full flex items-center gap-3 p-3 hover:bg-white/5 rounded-lg transition-colors duration-150 text-left"
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
            {/* Code File Tabs */}
            <div className="flex items-center gap-1 px-2 py-2 border-b border-white/10 overflow-x-auto scrollbar-hide"
              style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
            >
              {codeFiles.map((file) => (
                <button
                  key={file.id}
                  onClick={() => onCodeFileChange(file.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all duration-150 ${
                    file.id === activeCodeFileId
                      ? 'text-text-primary'
                      : 'text-text-secondary hover:text-text-primary'
                  }`}
                  style={{
                    background: file.id === activeCodeFileId
                      ? 'rgba(88, 166, 255, 0.15)'
                      : 'transparent',
                    border: file.id === activeCodeFileId
                      ? '1px solid rgba(88, 166, 255, 0.3)'
                      : '1px solid transparent',
                  }}
                >
                  {file.name}
                </button>
              ))}
            </div>

            {/* Code Content */}
            <div className="flex-1 overflow-auto scrollbar-dark p-4">
              <pre className="text-sm font-mono text-text-secondary">
                {activeCodeFile?.content}
              </pre>
            </div>
          </div>
        );

      case 'report':
        return (
          <div className="flex flex-col h-full">
            <div className="flex-1 overflow-y-auto scrollbar-dark p-4">
              <h3 className="text-lg font-semibold text-text-primary mb-4">
                Comprehensive Analysis Report
              </h3>
              <div className="space-y-4 text-sm text-text-secondary">
                <p>
                  This report provides a comprehensive analysis of the submitted ELF shared library,
                  identified as a malicious Pluggable Authentication Module (PAM).
                </p>
                <div className="p-4 rounded-xl" style={{ background: 'rgba(20, 28, 50, 0.4)', border: '1px solid rgba(100, 120, 180, 0.15)' }}>
                  <h4 className="font-semibold text-text-primary mb-2">1. Executive Summary</h4>
                  <p>
                    The analysis concludes with high confidence that the file is a malicious PAM designed
                    to function as a sophisticated backdoor and credential stealer on Linux systems.
                  </p>
                </div>
                <div className="p-4 rounded-xl" style={{ background: 'rgba(20, 28, 50, 0.4)', border: '1px solid rgba(100, 120, 180, 0.15)' }}>
                  <h4 className="font-semibold text-text-primary mb-2">2. Technical Deep Dive</h4>
                  <p>
                    The core malicious logic is located within the pam_sm_authenticate function,
                    which is the standard PAM function responsible for validating user credentials.
                  </p>
                </div>
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="h-full flex flex-col backdrop-blur-xl"
      style={{
        background: 'rgba(12, 16, 32, 0.9)',
      }}
    >
      {/* Header with Tabs */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/10"
        style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
      >
        <div className="flex items-center gap-1">
          {/* Resources Tab */}
          <button
            onClick={() => onTabChange('resources')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-150 ${
              activeTab === 'resources'
                ? 'text-text-primary'
                : 'text-text-secondary hover:text-text-primary'
            }`}
            style={{
              background: activeTab === 'resources'
                ? 'rgba(88, 166, 255, 0.15)'
                : 'transparent',
            }}
          >
            <LayoutGrid className="w-4 h-4" />
            <span>Resources</span>
          </button>

          {/* Analysis Tab */}
          <button
            onClick={() => onTabChange('code')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-150 ${
              activeTab === 'code'
                ? 'text-text-primary'
                : 'text-text-secondary hover:text-text-primary'
            }`}
            style={{
              background: activeTab === 'code'
                ? 'rgba(88, 166, 255, 0.15)'
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
        </div>

        <button
          onClick={onClose}
          className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-white/5 transition-all duration-150"
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
