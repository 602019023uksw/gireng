import { motion } from 'framer-motion';
import { X, Download, Copy, FileText, ChevronRight, Monitor, FileCode } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { useState } from 'react';

interface ReportViewerProps {
  title: string;
  fileHash: string;
  content: string;
  htmlUrl?: string;
  onClose: () => void;
}

export function ReportViewer({ title, fileHash, content, htmlUrl, onClose }: ReportViewerProps) {
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<'html' | 'markdown'>('html');

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${title.replace(/\s+/g, '_').toLowerCase()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const showHtml = htmlUrl && viewMode === 'html';

  return (
    <motion.div
      initial={{ opacity: 0, x: 50 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 50 }}
      transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
      className="w-[600px] h-screen flex flex-col backdrop-blur-xl"
      style={{
        background: 'rgba(12, 16, 32, 0.9)',
        borderLeft: '1px solid rgba(100, 120, 180, 0.15)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/10"
        style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
      >
        <div className="flex items-center gap-3">
          <div 
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
            style={{
              background: 'rgba(20, 28, 50, 0.5)',
              border: '1px solid rgba(100, 120, 180, 0.2)',
            }}
          >
            <FileText className="w-4 h-4 text-text-secondary" />
            <span className="text-sm font-medium text-text-primary">Resources</span>
          </div>
          <ChevronRight className="w-4 h-4 text-text-muted" />
          <span className="text-sm text-text-secondary truncate max-w-[200px]">{title}</span>
          <span 
            className="px-2 py-0.5 rounded text-xs"
            style={{
              background: 'rgba(100, 120, 180, 0.15)',
              color: 'rgba(160, 168, 184, 0.8)',
            }}
          >
            {showHtml ? 'html' : 'markdown'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {htmlUrl && (
            <div className="flex items-center bg-white/5 rounded-lg p-0.5 mr-1">
              <button
                onClick={() => setViewMode('html')}
                className={`w-7 h-7 rounded flex items-center justify-center transition-all ${
                  viewMode === 'html' ? 'bg-white/10 text-text-primary' : 'text-text-secondary hover:text-text-primary'
                }`}
                title="Styled HTML view"
              >
                <Monitor className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setViewMode('markdown')}
                className={`w-7 h-7 rounded flex items-center justify-center transition-all ${
                  viewMode === 'markdown' ? 'bg-white/10 text-text-primary' : 'text-text-secondary hover:text-text-primary'
                }`}
                title="Raw markdown view"
              >
                <FileCode className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
          <button
            onClick={handleDownload}
            className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-white/5 transition-all duration-150"
          >
            <Download className="w-4 h-4" />
          </button>
          <button
            onClick={handleCopy}
            className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-white/5 transition-all duration-150"
          >
            {copied ? (
              <motion.div
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                className="text-accent-green"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </motion.div>
            ) : (
              <Copy className="w-4 h-4" />
            )}
          </button>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-white/5 transition-all duration-150"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Report Content */}
      <div className="flex-1 overflow-hidden">
        {showHtml ? (
          <iframe
            src={htmlUrl}
            className="w-full h-full border-0"
            title="Analysis Report"
            sandbox="allow-scripts allow-same-origin"
          />
        ) : (
          <div className="h-full overflow-y-auto scrollbar-dark p-6">
            {/* Title Section */}
            <div className="mb-6 pb-6 border-b border-white/10"
              style={{ borderColor: 'rgba(100, 120, 180, 0.15)' }}
            >
              <h1 className="text-2xl font-bold text-text-primary mb-3">{title}</h1>
              <div className="flex items-center gap-2 text-sm">
                <span className="text-text-muted">File Hash (SHA256):</span>
                <span className="text-text-secondary font-mono">{fileHash}</span>
              </div>
            </div>

            {/* Markdown Content */}
            <div className="prose prose-invert prose-sm max-w-none">
              <ReactMarkdown
                components={{
                  h1: ({ children }) => (
                    <h1 className="text-xl font-bold text-text-primary mt-8 mb-4">{children}</h1>
                  ),
                  h2: ({ children }) => (
                    <h2 className="text-lg font-semibold text-text-primary mt-6 mb-3">{children}</h2>
                  ),
                  h3: ({ children }) => (
                    <h3 className="text-base font-semibold text-text-primary mt-4 mb-2">{children}</h3>
                  ),
                  p: ({ children }) => (
                    <p className="text-sm text-text-secondary leading-relaxed mb-4">{children}</p>
                  ),
                  code: ({ children }) => (
                    <code 
                      className="px-1.5 py-0.5 rounded text-xs font-mono"
                      style={{
                        background: 'rgba(88, 166, 255, 0.1)',
                        border: '1px solid rgba(88, 166, 255, 0.2)',
                        color: '#F0F6FC',
                      }}
                    >
                      {children}
                    </code>
                  ),
                  pre: ({ children }) => (
                    <pre 
                      className="p-4 rounded-lg overflow-x-auto my-4"
                      style={{
                        background: 'rgba(10, 14, 28, 0.6)',
                        border: '1px solid rgba(100, 120, 180, 0.15)',
                      }}
                    >
                      {children}
                    </pre>
                  ),
                  hr: () => (
                    <hr className="my-6 border-white/10" style={{ borderColor: 'rgba(100, 120, 180, 0.15)' }} />
                  ),
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
}

export default ReportViewer;
