import { motion } from 'framer-motion';
import { BarChart3, Code2, Workflow, Shield, Hash } from 'lucide-react';
import type { QuickAction } from '@/types';

interface QuickActionChipsProps {
  actions: QuickAction[];
  onActionClick?: (actionId: string) => void;
}

const iconMap: Record<string, React.ElementType> = {
  BarChart3,
  Code2,
  Workflow,
  Shield,
  Hash,
};

export function QuickActionChips({ actions, onActionClick }: QuickActionChipsProps) {
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
            delayChildren: 0.3,
          },
        },
      }}
      className="flex items-center gap-2 overflow-x-auto scrollbar-hide py-2"
    >
      {actions.map((action) => {
        const Icon = iconMap[action.icon] || BarChart3;
        return (
          <motion.button
            key={action.id}
            variants={{
              hidden: { opacity: 0, y: 10 },
              visible: { opacity: 1, y: 0 },
            }}
            transition={{ duration: 0.3 }}
            onClick={() => onActionClick?.(action.id)}
            className="flex items-center gap-2 px-4 py-2 rounded-full text-text-secondary text-sm whitespace-nowrap transition-all duration-150 hover:text-accent-blue hover:shadow-glass"
            style={{
              background: '#ffffff',
              border: '1px solid #dadce0',
            }}
          >
            <Icon className="w-4 h-4" />
            <span>{action.label}</span>
          </motion.button>
        );
      })}
    </motion.div>
  );
}

export default QuickActionChips;
