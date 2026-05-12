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
    <div className="relative flex items-center gap-2 rounded-full border border-border-default bg-white p-1 shadow-xs">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onTabChange(tab.id)}
          className={`relative rounded-full px-4 py-2 text-sm font-medium transition-colors duration-150 ${
            activeTab === tab.id
              ? 'text-accent-blue'
              : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
          }`}
        >
          {activeTab === tab.id && (
            <motion.div
              layoutId="tab-pill"
              className="absolute inset-0 rounded-full bg-blue-50"
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
            />
          )}
          <span className="relative z-10">
          {tab.label}
          </span>
        </button>
      ))}
    </div>
  );
}

export default AnalysisTabs;
