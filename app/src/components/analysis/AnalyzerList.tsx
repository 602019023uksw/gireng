import { motion } from 'framer-motion';
import { AnalyzerItem } from './AnalyzerItem';
import type { Analyzer } from '@/types';

interface AnalyzerListProps {
  analyzers: Analyzer[];
}

export function AnalyzerList({ analyzers }: AnalyzerListProps) {
  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={{
        hidden: { opacity: 0 },
        visible: {
          opacity: 1,
          transition: {
            staggerChildren: 0.05,
            delayChildren: 0.1,
          },
        },
      }}
      className="rounded-3xl overflow-hidden bg-white"
      style={{
        border: '1px solid #e8eaed',
        boxShadow: '0 1px 3px rgba(60, 64, 67, 0.16), 0 1px 2px rgba(60, 64, 67, 0.08)',
      }}
    >
      {analyzers.map((analyzer) => (
        <motion.div 
          key={analyzer.id} 
          variants={{
            hidden: { opacity: 0, y: 10 },
            visible: { opacity: 1, y: 0 },
          }}
          transition={{ duration: 0.3 }}
        >
          <AnalyzerItem analyzer={analyzer} />
        </motion.div>
      ))}
    </motion.div>
  );
}

export default AnalyzerList;
