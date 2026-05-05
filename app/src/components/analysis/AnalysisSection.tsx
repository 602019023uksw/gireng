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
      <h3 className="text-lg font-semibold text-text-primary mb-4 tracking-tight">{title}</h3>
      <div 
        className="rounded-3xl bg-white p-6"
        style={{
          border: '1px solid #e8eaed',
          boxShadow: '0 1px 3px rgba(60, 64, 67, 0.16), 0 1px 2px rgba(60, 64, 67, 0.08)',
        }}
      >
        {children}
      </div>
    </motion.section>
  );
}

export default AnalysisSection;
