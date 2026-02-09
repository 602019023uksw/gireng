import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronRight, ExternalLink } from 'lucide-react';
import type { Analyzer } from '@/types';

interface AnalyzerItemProps {
  analyzer: Analyzer;
}

const verdictColors: Record<string, string> = {
  Clean: 'text-accent-green',
  Malware: 'text-accent-red',
  Malicious: 'text-accent-red',
  Suspicious: 'text-accent-orange',
  'Potentially Unwanted': 'text-accent-orange',
  Not_extracted: 'text-text-muted',
};

export function AnalyzerItem({ analyzer }: AnalyzerItemProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="border-b border-white/10 last:border-b-0"
      style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
    >
      {/* Header Row */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-4 py-4 hover:bg-white/5 transition-colors duration-150"
      >
        <div className="flex items-center gap-3">
          <motion.div
            animate={{ rotate: isExpanded ? 90 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronRight className="w-4 h-4 text-text-secondary" />
          </motion.div>
          
          <div className="text-left">
            <h4 className="text-sm font-semibold text-text-primary">{analyzer.name}</h4>
            <p className="text-xs text-text-muted mt-0.5">
              By {analyzer.source}{' '}
              <a 
                href={analyzer.sourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent-blue hover:underline inline-flex items-center gap-0.5"
                onClick={(e) => e.stopPropagation()}
              >
                {analyzer.sourceUrl}
                <ExternalLink className="w-3 h-3" />
              </a>
            </p>
          </div>
        </div>

        <div className="text-right">
          <p className="text-xs text-text-muted uppercase tracking-wider">VERDICT</p>
          <p className={`text-sm font-semibold ${verdictColors[analyzer.verdict] || 'text-text-muted'}`}>
            {analyzer.verdict}
          </p>
        </div>
      </button>

      {/* Expanded Content */}
      <AnimatePresence>
        {isExpanded && analyzer.details && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
            className="overflow-hidden"
            style={{
              background: 'rgba(8, 10, 18, 0.6)',
            }}
          >
            <div className="px-12 py-6 space-y-6">
              {/* Analysis Findings Label */}
              <p className="text-xs font-medium text-text-muted uppercase tracking-wider">
                ANALYSIS FINDINGS
              </p>

              {/* Executive Summary */}
              <section>
                <h5 className="text-lg font-semibold text-text-primary mb-3">
                  Executive Summary
                </h5>
                <p className="text-sm text-text-secondary leading-relaxed">
                  {analyzer.details.executiveSummary}
                </p>
              </section>

              {/* Static Analysis */}
              <section>
                <h5 className="text-lg font-semibold text-text-primary mb-3">
                  Static Analysis
                </h5>
                <div className="text-sm text-text-secondary leading-relaxed whitespace-pre-line">
                  {analyzer.details.staticAnalysis.split('\n').map((line, index) => (
                    <p key={index} className={line.startsWith('•') ? 'ml-4 mt-2' : 'mt-2'}>
                      {line.includes('__') ? (
                        <>
                          {line.split(/(__.*?__)/).map((part, i) => 
                            part.startsWith('__') && part.endsWith('__') ? (
                              <code key={i} className="px-1.5 py-0.5 rounded text-text-primary font-mono text-xs"
                                style={{
                                  background: 'rgba(88, 166, 255, 0.1)',
                                  border: '1px solid rgba(88, 166, 255, 0.2)',
                                }}
                              >
                                {part.replace(/__/g, '')}
                              </code>
                            ) : (
                              part
                            )
                          )}
                        </>
                      ) : (
                        line
                      )}
                    </p>
                  ))}
                </div>
              </section>

              {/* Behavioral Analysis */}
              <section>
                <h5 className="text-lg font-semibold text-text-primary mb-3">
                  Behavioral Analysis
                </h5>
                <p className="text-sm text-text-secondary leading-relaxed">
                  {analyzer.details.behavioralAnalysis}
                </p>
              </section>

              {/* IOCs */}
              <section>
                <h5 className="text-lg font-semibold text-text-primary mb-3">
                  Indicators of Compromise (IOCs)
                </h5>
                <p className="text-sm text-text-secondary leading-relaxed">
                  {analyzer.details.iocs}
                </p>
              </section>

              {/* Conclusion */}
              <section>
                <h5 className="text-lg font-semibold text-text-primary mb-3">
                  Conclusion
                </h5>
                <p className="text-sm text-text-secondary leading-relaxed">
                  {analyzer.details.conclusion}
                </p>
              </section>

              {/* Execution Logs */}
              <div className="pt-4 border-t border-white/10"
                style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
              >
                <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">
                  EXECUTION LOGS
                </p>
                <div className="font-mono text-xs text-text-muted">
                  {analyzer.details.executionLogs.map((log, index) => (
                    <p key={index} className="flex items-center gap-2">
                      <span>›</span>
                      <span className="italic">{log}</span>
                    </p>
                  ))}
                </div>
                <div className="flex items-center justify-end gap-2 mt-2 text-xs text-text-muted">
                  <span>1 LINES</span>
                  <ChevronRight className="w-3 h-3" />
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default AnalyzerItem;
