import { motion } from 'framer-motion';
import { CheckCircle2, FileText, ChevronRight, Download, FileCode, FileType } from 'lucide-react';
import { getExportHtmlUrl, getExportPdfUrl } from '@/lib/api';

interface AnalysisCompletedCardProps {
  fileHash: string;
  progress: number;
  maxProgress: number;
  onViewMore?: () => void;
}

export function AnalysisCompletedCard({
  fileHash,
  progress,
  maxProgress,
  onViewMore,
}: AnalysisCompletedCardProps) {
  const progressPercent = (progress / maxProgress) * 100;
  const shortHash = fileHash ? `${fileHash.slice(0, 16)}…${fileHash.slice(-8)}` : '';

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.2 }}
      className="rounded-xl overflow-hidden my-3"
      style={{
        background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.6) 0%, rgba(15, 20, 35, 0.4) 100%)',
        border: '1px solid rgba(100, 120, 180, 0.2)',
        backdropFilter: 'blur(8px)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/5"
        style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
      >
        <div className="flex items-center gap-3">
          <div 
            className="w-6 h-6 rounded-full flex items-center justify-center"
            style={{
              background: 'linear-gradient(135deg, rgba(63, 185, 80, 0.2) 0%, rgba(63, 185, 80, 0.1) 100%)',
              border: '1px solid rgba(63, 185, 80, 0.3)',
            }}
          >
            <CheckCircle2 className="w-4 h-4 text-accent-green" />
          </div>
          <span className="text-sm font-medium text-text-primary">Analysis completed</span>
        </div>
        <button
          onClick={onViewMore}
          className="flex items-center gap-1 text-sm text-accent-blue hover:underline"
        >
          View more
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>

      {/* Content */}
      <div className="p-4 space-y-3">
        {/* File hash */}
        <div className="flex items-start gap-3">
          <FileText className="w-5 h-5 text-text-secondary mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-xs text-text-muted mb-0.5">SHA-256</p>
            <p className="text-sm text-text-primary font-mono truncate" title={fileHash}>{shortHash}</p>
          </div>
        </div>

        {/* Progress */}
        <div>
          <div className="flex items-center justify-between text-xs text-text-secondary mb-1">
            <span>Analyzers Progress</span>
            <span>{progress}/{maxProgress}</span>
          </div>
          <div 
            className="h-1.5 rounded-full overflow-hidden"
            style={{ background: 'rgba(8, 10, 18, 0.5)' }}
          >
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progressPercent}%` }}
              transition={{ duration: 0.8, ease: [0.4, 0, 0.2, 1] }}
              className="h-full rounded-full"
              style={{ background: 'linear-gradient(90deg, #58A6FF, #A371F7)' }}
            />
          </div>
        </div>

        {/* Export buttons */}
        {fileHash && (
          <div className="flex items-center gap-2 pt-1">
            <span className="text-xs text-text-muted mr-1">
              <Download className="w-3.5 h-3.5 inline -mt-0.5 mr-1" />
              Export:
            </span>
            <a
              href={getExportHtmlUrl(fileHash)}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors duration-150 hover:brightness-125"
              style={{
                background: 'rgba(59, 130, 246, 0.12)',
                color: 'rgb(147, 197, 253)',
                border: '1px solid rgba(59, 130, 246, 0.25)',
              }}
            >
              <FileCode className="w-3.5 h-3.5" />
              HTML
            </a>
            <a
              href={getExportPdfUrl(fileHash)}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors duration-150 hover:brightness-125"
              style={{
                background: 'rgba(239, 68, 68, 0.12)',
                color: 'rgb(252, 165, 165)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
              }}
            >
              <FileType className="w-3.5 h-3.5" />
              PDF
            </a>
          </div>
        )}
      </div>
    </motion.div>
  );
}

export default AnalysisCompletedCard;
