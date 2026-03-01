import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Code2, ChevronUp, FileText } from 'lucide-react';
import type { ToolCall } from '@/types';

interface ToolCallCardProps {
  tool: ToolCall;
}

function formatEta(seconds: number): string {
  const safe = Math.max(0, Math.round(seconds));
  const mins = Math.floor(safe / 60);
  const secs = safe % 60;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

function getResultFileId(result: unknown): string | null {
  if (!result || typeof result !== 'object') return null;
  const maybeFileId = (result as { fileId?: unknown }).fileId;
  return typeof maybeFileId === 'string' ? maybeFileId : null;
}

export function ToolCallCard({ tool }: ToolCallCardProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const resultFileId = getResultFileId(tool.result);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.1, ease: [0.4, 0, 0.2, 1] as const }}
      className="rounded-xl overflow-hidden mb-3"
      style={{
        background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.5) 0%, rgba(15, 20, 35, 0.35) 100%)',
        border: '1px solid rgba(100, 120, 180, 0.15)',
        backdropFilter: 'blur(8px)',
      }}
    >
      {/* Card Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors duration-150"
      >
        <div className="flex items-center gap-3">
          <Code2 className="w-5 h-5 text-text-secondary" />
          <span className="text-sm font-medium text-text-primary">{tool.name}</span>
          <span className="text-xs text-accent-blue">{'{ }'}</span>
        </div>
        <motion.div
          animate={{ rotate: isExpanded ? 180 : 0 }}
          transition={{ duration: 0.2 }}
        >
          <ChevronUp className="w-4 h-4 text-text-secondary" />
        </motion.div>
      </button>

      {/* Card Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4">
              {/* Status */}
              <div 
                className="rounded-lg p-3 mb-3"
                style={{
                  background: 'rgba(8, 10, 18, 0.5)',
                  border: '1px solid rgba(100, 120, 180, 0.1)',
                }}
              >
                <p className="text-sm text-text-primary">
                  {tool.status === 'running' && 'The file is being analyzed'}
                  {tool.status === 'completed' && 'Analysis completed successfully'}
                  {tool.status === 'failed' && 'Analysis failed'}
                  {tool.status === 'pending' && 'Waiting to start analysis...'}
                </p>
              </div>

              {/* Progress Bar */}
              {tool.status === 'running' && tool.progress !== undefined && (
                <div className="mb-3">
                  <div className="flex items-center justify-between text-xs text-text-secondary mb-1">
                    <span>Analyzers Progress</span>
                    <span>{tool.progress}/{tool.maxProgress || 7}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-text-muted mb-1">
                    <span>{tool.phase ? `Phase: ${tool.phase}` : 'Phase: working'}</span>
                    <span>{tool.etaSeconds !== undefined ? `ETA ${formatEta(tool.etaSeconds)}` : 'ETA estimating...'}</span>
                  </div>
                  <div 
                    className="h-1.5 rounded-full overflow-hidden"
                    style={{ background: 'rgba(8, 10, 18, 0.5)' }}
                  >
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(tool.progress / (tool.maxProgress || 7)) * 100}%` }}
                      transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] as const }}
                      className="h-full rounded-full"
                      style={{ background: 'linear-gradient(90deg, #58A6FF, #A371F7)' }}
                    />
                  </div>
                </div>
              )}

              {/* Result Preview */}
              {tool.status === 'completed' && resultFileId && (
                <div 
                  className="flex items-center gap-3 p-3 rounded-lg"
                  style={{
                    background: 'rgba(8, 10, 18, 0.5)',
                    border: '1px solid rgba(100, 120, 180, 0.1)',
                  }}
                >
                  <FileText className="w-5 h-5 text-text-secondary" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-text-primary truncate">
                      {resultFileId.substring(0, 50)}...
                    </p>
                    <p className="text-xs text-text-muted">Sent for analysis...</p>
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default ToolCallCard;
