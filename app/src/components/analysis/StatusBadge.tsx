import { motion } from 'framer-motion';

type StatusType = 'Clean' | 'Malware' | 'Suspicious' | 'Not_extracted' | 'COMPLETED' | 'running' | 'pending' | string;

interface StatusBadgeProps {
  status: StatusType;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
}

const verdictColors: Record<string, string> = {
  Clean: 'text-accent-green',
  Malware: 'text-accent-red',
  Malicious: 'text-accent-red',
  Suspicious: 'text-accent-orange',
  'Potentially Unwanted': 'text-accent-orange',
  Not_extracted: 'text-text-muted',
  COMPLETED: 'text-accent-green',
  running: 'text-accent-blue',
  pending: 'text-text-muted',
};

const verdictBgColors: Record<string, string> = {
  Clean: 'bg-accent-green/10',
  Malware: 'bg-accent-red/10',
  Malicious: 'bg-accent-red/10',
  Suspicious: 'bg-accent-orange/10',
  'Potentially Unwanted': 'bg-accent-orange/10',
  Not_extracted: 'bg-text-muted/10',
  COMPLETED: 'bg-accent-green/10',
  running: 'bg-accent-blue/10',
  pending: 'bg-text-muted/10',
};

const dotColors: Record<string, string> = {
  Clean: '#3FB950',
  Malware: '#F85149',
  Malicious: '#F85149',
  Suspicious: '#D29922',
  COMPLETED: '#3FB950',
  running: '#58A6FF',
};

export function StatusBadge({ status, size = 'md', showDot = false }: StatusBadgeProps) {
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-3 py-1',
    lg: 'text-base px-4 py-1.5',
  };

  const colorClass = verdictColors[status] || 'text-text-muted';
  const bgClass = verdictBgColors[status] || 'bg-text-muted/10';
  const dotColor = dotColors[status];

  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.2 }}
      className={`inline-flex items-center gap-2 rounded-full font-medium ${colorClass} ${bgClass} ${sizeClasses[size]}`}
    >
      {showDot && dotColor && (
        <span 
          className="w-2 h-2 rounded-full"
          style={{ backgroundColor: dotColor }}
        />
      )}
      {status}
    </motion.span>
  );
}

export default StatusBadge;
