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
      className="rounded-2xl overflow-hidden my-3 bg-white"
      style={{
        border: '1px solid #e8eaed',
        boxShadow: '0 1px 3px rgba(60, 64, 67, 0.12)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b"
        style={{ borderColor: '#e8eaed' }}
      >
        <div className="flex items-center gap-3">
          <div 
            className="w-6 h-6 rounded-full flex items-center justify-center"
            style={{
              background: '#e6f4ea',
              border: '1px solid #ceead6',
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
            style={{ background: '#e8eaed' }}
          >
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progressPercent}%` }}
              transition={{ duration: 0.8, ease: [0.4, 0, 0.2, 1] }}
              className="h-full rounded-full"
              style={{ background: '#1a73e8' }}
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
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-colors duration-150 hover:bg-blue-100"
              style={{
                background: '#e8f0fe',
                color: '#1a73e8',
                border: '1px solid #d2e3fc',
              }}
            >
              <FileCode className="w-3.5 h-3.5" />
              HTML
            </a>
            <a
              href={getExportPdfUrl(fileHash)}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-colors duration-150 hover:bg-red-100"
              style={{
                background: '#fce8e6',
                color: '#d93025',
                border: '1px solid #fad2cf',
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
