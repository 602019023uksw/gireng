import { motion } from 'framer-motion';
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
      className="rounded-3xl bg-white p-7"
      style={{
        border: '1px solid #e8eaed',
        boxShadow: '0 8px 24px rgba(60, 64, 67, 0.12), 0 2px 6px rgba(60, 64, 67, 0.08)',
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
          label="gireng Final Verdict"
        />

        {/* File Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <h2 className="text-xl font-semibold text-text-primary font-mono break-all tracking-tight">
                {analysis.hash}
              </h2>
              <p className="text-sm text-text-muted mt-1 font-mono">
                {analysis.hash} <span className="mx-2">•</span> {analysis.size} <span className="mx-2">•</span> {analysis.type}
              </p>
            </div>
          </div>

          {/* Verdict Badge */}
          <div className="mt-4">
            <StatusBadge status={analysis.verdict} size="md" />
          </div>
        </div>
      </div>

      {/* Metadata Grid */}
      <div className="grid grid-cols-4 gap-4 mb-6 py-4 border-y"
        style={{ borderColor: '#e8eaed' }}
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
