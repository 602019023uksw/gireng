import type { ReactNode } from 'react';
import { motion } from 'framer-motion';

interface MainLayoutProps {
  children: ReactNode;
  sidebar: ReactNode;
  rightPanel?: ReactNode;
}

export function MainLayout({ children, sidebar, rightPanel }: MainLayoutProps) {
  return (
    <div className="flex h-screen bg-bg-primary overflow-hidden text-text-primary">
      {/* Sidebar */}
      <motion.div
        initial={{ x: -20, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
      >
        {sidebar}
      </motion.div>

      {/* Main Content */}
      <motion.main
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4, delay: 0.1, ease: [0.4, 0, 0.2, 1] as const }}
        className="flex-1 flex flex-col min-w-0"
      >
        {children}
      </motion.main>

      {/* Right Panel */}
      {rightPanel && (
        <motion.div
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ duration: 0.3, delay: 0.2, ease: [0.4, 0, 0.2, 1] as const }}
        >
          {rightPanel}
        </motion.div>
      )}
    </div>
  );
}

export default MainLayout;
