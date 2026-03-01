import { motion } from 'framer-motion';

interface AnalysisTabsProps {
  activeTab: 'overview' | 'analyzers' | 'callgraph' | 'dynamic';
  onTabChange: (tab: 'overview' | 'analyzers' | 'callgraph' | 'dynamic') => void;
  hasDynamicData?: boolean;
}

export function AnalysisTabs({ activeTab, onTabChange, hasDynamicData }: AnalysisTabsProps) {
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'analyzers', label: 'Analyzers Details' },
    { id: 'callgraph', label: 'Call Graph' },
    ...(hasDynamicData ? [{ id: 'dynamic' as const, label: 'Dynamic Analysis' }] : []),
  ] as const;

  return (
    <div className="relative flex items-center gap-6 border-b border-border-default">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onTabChange(tab.id)}
          className={`relative py-3 text-sm font-medium transition-colors duration-150 ${
            activeTab === tab.id
              ? 'text-text-primary'
              : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          {tab.label}
          {activeTab === tab.id && (
            <motion.div
              layoutId="tab-underline"
              className="absolute bottom-0 left-0 right-0 h-0.5 bg-accent-blue"
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
            />
          )}
        </button>
      ))}
    </div>
  );
}

export default AnalysisTabs;
