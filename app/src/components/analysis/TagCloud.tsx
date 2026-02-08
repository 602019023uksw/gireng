import { motion } from 'framer-motion';

interface TagCloudProps {
  tags: string[];
  maxVisible?: number;
}

export function TagCloud({ tags, maxVisible }: TagCloudProps) {
  const visibleTags = maxVisible ? tags.slice(0, maxVisible) : tags;
  const remainingCount = maxVisible ? tags.length - maxVisible : 0;

  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={{
        hidden: { opacity: 0 },
        visible: {
          opacity: 1,
          transition: {
            staggerChildren: 0.02,
            delayChildren: 0.3,
          },
        },
      }}
      className="flex flex-wrap gap-1.5"
    >
      {visibleTags.map((tag, index) => (
        <motion.span
          key={`${tag}-${index}`}
          variants={{
            hidden: { opacity: 0, scale: 0.8 },
            visible: { opacity: 1, scale: 1 },
          }}
          transition={{ duration: 0.2 }}
          className="px-2.5 py-1 text-xs font-medium rounded-full transition-all duration-150 cursor-default backdrop-blur-sm"
          style={{
            background: 'rgba(88, 166, 255, 0.08)',
            border: '1px solid rgba(88, 166, 255, 0.15)',
            color: 'rgba(160, 168, 184, 0.9)',
          }}
        >
          {tag}
        </motion.span>
      ))}
      {remainingCount > 0 && (
        <motion.span
          variants={{
            hidden: { opacity: 0, scale: 0.8 },
            visible: { opacity: 1, scale: 1 },
          }}
          transition={{ duration: 0.2 }}
          className="px-2.5 py-1 text-xs font-medium rounded-full backdrop-blur-sm"
          style={{
            background: 'rgba(100, 120, 180, 0.1)',
            border: '1px solid rgba(100, 120, 180, 0.2)',
            color: 'rgba(160, 168, 184, 0.7)',
          }}
        >
          +{remainingCount}
        </motion.span>
      )}
    </motion.div>
  );
}

export default TagCloud;
