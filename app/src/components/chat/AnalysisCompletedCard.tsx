import { motion } from 'framer-motion';
import { CheckCircle2, FileText, ChevronRight } from 'lucide-react';

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
        {/* File info */}
        <div className="flex items-start gap-3">
          <FileText className="w-5 h-5 text-text-secondary mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm text-text-secondary">File:</p>
            <p className="text-sm text-text-primary font-mono truncate">{fileHash}</p>
          </div>
        </div>

        <div className="flex items-start gap-3">
          <div className="w-5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm text-text-secondary">Hash:</p>
            <p className="text-sm text-text-primary font-mono truncate">{fileHash}</p>
          </div>
        </div>

        {/* Progress */}
        <div className="pt-2">
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
      </div>
    </motion.div>
  );
}

export default AnalysisCompletedCard;
