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
      className="backdrop-blur-xl rounded-2xl overflow-hidden"
      style={{
        background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.5) 0%, rgba(15, 20, 35, 0.3) 100%)',
        border: '1px solid rgba(100, 120, 180, 0.15)',
        boxShadow: '0 8px 32px -4px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.03) inset',
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
