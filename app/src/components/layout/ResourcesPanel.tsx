import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  FolderOpen, 
  FileText, 
  FileCode, 
  ChevronDown, 
  ChevronRight,
  X,
  LayoutGrid,
  FileCheck
} from 'lucide-react';
import type { FileNode, Analysis, Report } from '@/types';
import { TagCloud } from '@/components/analysis/TagCloud';

interface ResourcesPanelProps {
  files: FileNode[];
  analyses: Analysis[];
  reports: Report[];
  isOpen: boolean;
  onClose: () => void;
  onFileClick?: (fileId: string) => void;
  onReportClick?: (reportId: string) => void;
}

interface ResourceSectionProps {
  title: string;
  icon: React.ElementType;
  count: number;
  children: React.ReactNode;
  defaultExpanded?: boolean;
}

function ResourceSection({ title, icon: Icon, count, children, defaultExpanded = true }: ResourceSectionProps) {
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
            transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
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
    if (node.type === 'code') return <FileCode className="w-4 h-4 text-accent-green" />;
    return <FileText className="w-4 h-4 text-text-secondary" />;
  };

  const handleClick = () => {
    if (hasChildren) {
      setIsExpanded(!isExpanded);
    } else if (onFileClick && node.type === 'code') {
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

export function ResourcesPanel({ 
  files, 
  analyses, 
  reports, 
  isOpen, 
  onClose, 
  onFileClick,
  onReportClick 
}: ResourcesPanelProps) {
  if (!isOpen) return null;

  return (
    <motion.aside
      initial={{ x: 300, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 300, opacity: 0 }}
      transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
      className="w-[380px] h-screen flex flex-col flex-shrink-0"
      style={{
        background: 'rgba(255, 255, 255, 0.96)',
        borderLeft: '1px solid #e8eaed',
        boxShadow: '-1px 0 2px rgba(60, 64, 67, 0.06)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b"
        style={{ borderColor: '#e8eaed' }}
      >
        <div className="flex items-center gap-3">
          <div 
            className="flex items-center gap-2 px-3 py-1.5 rounded-full"
            style={{
              background: '#f8fafd',
              border: '1px solid #e8eaed',
            }}
          >
            <LayoutGrid className="w-4 h-4 text-text-secondary" />
            <span className="text-sm font-medium text-text-primary">Resources</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 text-text-secondary">
            <span className="text-sm">Analysis: ...</span>
          </div>
        </div>
        <button
          onClick={onClose}
          className="w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-accent-blue hover:bg-bg-hover transition-all duration-150"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto scrollbar-dark p-4">
        {/* Analyzed Files */}
        <ResourceSection title="Analyzed Files" icon={FolderOpen} count={files.length}>
          {files.map((file) => (
            <FileTreeItem 
              key={file.id} 
              node={file} 
              onFileClick={onFileClick}
            />
          ))}
        </ResourceSection>

        {/* Analyses */}
        <ResourceSection title="Analyses" icon={FileCheck} count={analyses.length}>
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
        </ResourceSection>

        {/* Reports */}
        <ResourceSection title="Reports" icon={FileText} count={reports.length}>
          {reports.map((report) => (
            <button
              key={report.id}
              onClick={() => onReportClick?.(report.id)}
              className="w-full flex items-center gap-3 p-3 hover:bg-bg-hover rounded-xl transition-colors duration-150 text-left"
            >
              <FileText className="w-5 h-5 text-text-secondary" />
              <span className="text-sm text-text-primary">{report.name}</span>
            </button>
          ))}
        </ResourceSection>
      </div>
    </motion.aside>
  );
}

export default ResourcesPanel;
