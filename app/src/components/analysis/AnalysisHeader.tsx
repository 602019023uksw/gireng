import { motion } from 'framer-motion';
import { Maximize2 } from 'lucide-react';
import { CircularProgress } from './CircularProgress';
import { StatusBadge } from './StatusBadge';
import { TagCloud } from './TagCloud';
import type { AnalysisResult } from '@/types';

interface AnalysisHeaderProps {
  analysis: AnalysisResult;
}

export function AnalysisHeader({ analysis }: AnalysisHeaderProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] as const }}
      className="backdrop-blur-xl rounded-2xl p-6"
      style={{
        background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.6) 0%, rgba(15, 20, 35, 0.4) 100%)',
        border: '1px solid rgba(100, 120, 180, 0.2)',
        boxShadow: '0 8px 32px -4px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.03) inset',
      }}
    >
      {/* Top Row: Progress and File Info */}
      <div className="flex items-start gap-6 mb-6">
        {/* Circular Progress */}
        <CircularProgress
          value={analysis.threatScore}
          max={analysis.maxScore}
          size={120}
          strokeWidth={10}
          color="#F85149"
          label="Ireng Final Verdict"
        />

        {/* File Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <h2 className="text-xl font-semibold text-text-primary font-mono break-all">
                {analysis.hash}
              </h2>
              <p className="text-sm text-text-muted mt-1 font-mono">
                {analysis.hash} <span className="mx-2">•</span> {analysis.size} <span className="mx-2">•</span> {analysis.type}
              </p>
            </div>
            <button className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-white/5 transition-all duration-150 flex-shrink-0">
              <Maximize2 className="w-4 h-4" />
            </button>
          </div>

          {/* Verdict Badge */}
          <div className="mt-4">
            <StatusBadge status={analysis.verdict} size="md" />
          </div>
        </div>
      </div>

      {/* Metadata Grid */}
      <div className="grid grid-cols-4 gap-4 mb-6 py-4 border-y border-white/10"
        style={{ borderColor: 'rgba(100, 120, 180, 0.15)' }}
      >
        <div>
          <p className="text-xs text-text-muted uppercase tracking-wider mb-1">STATUS</p>
          <StatusBadge status={analysis.status} size="sm" showDot />
        </div>
        <div>
          <p className="text-xs text-text-muted uppercase tracking-wider mb-1">DURATION</p>
          <p className="text-sm text-text-primary font-medium">{analysis.duration || '—'}</p>
        </div>
        <div>
          <p className="text-xs text-text-muted uppercase tracking-wider mb-1">STARTED</p>
          <p className="text-sm text-text-primary font-medium">{analysis.started || '—'}</p>
        </div>
        <div>
          <p className="text-xs text-text-muted uppercase tracking-wider mb-1">COMPLETED</p>
          <p className="text-sm text-text-primary font-medium">{analysis.completed || '—'}</p>
        </div>
      </div>

      {/* Tags */}
      <div>
        <TagCloud tags={analysis.tags} />
      </div>
    </motion.div>
  );
}

export default AnalysisHeader;
