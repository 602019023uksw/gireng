import { motion } from 'framer-motion';

interface AnalysisSectionProps {
  title: string;
  children: React.ReactNode;
}

export function AnalysisSection({ title, children }: AnalysisSectionProps) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] as const }}
      className="mb-8"
    >
      <h3 className="text-lg font-semibold text-text-primary mb-4">{title}</h3>
      <div 
        className="backdrop-blur-xl rounded-2xl p-6"
        style={{
          background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.5) 0%, rgba(15, 20, 35, 0.3) 100%)',
          border: '1px solid rgba(100, 120, 180, 0.15)',
          boxShadow: '0 8px 32px -4px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.03) inset',
        }}
      >
        {children}
      </div>
    </motion.section>
  );
}

export default AnalysisSection;
