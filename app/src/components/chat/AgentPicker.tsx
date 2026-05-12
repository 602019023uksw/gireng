import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Binary, Terminal, Search, Shield, FileCode, Hash, Sparkles } from 'lucide-react';
import { agents } from '@/agents/ghidra-agent';

interface AgentPickerProps {
  isOpen: boolean;
  searchQuery: string;
  onSelect: (agentId: string) => void;
  onClose: () => void;
}

const iconMap: Record<string, React.ElementType> = {
  Binary,
  Terminal,
  Search,
  Shield,
  FileCode,
  Hash,
  Sparkles,
};

export function AgentPicker({ isOpen, searchQuery, onSelect, onClose }: AgentPickerProps) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  // Filter agents based on search query
  const filteredAgents = agents.filter(agent =>
    agent.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    agent.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
    agent.capabilities.some(cap => cap.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const effectiveSelectedIndex = Math.min(
    selectedIndex,
    Math.max(filteredAgents.length - 1, 0),
  );

  // Handle keyboard navigation
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setSelectedIndex(prev => 
            prev < filteredAgents.length - 1 ? prev + 1 : prev
          );
          break;
        case 'ArrowUp':
          e.preventDefault();
          setSelectedIndex(prev => prev > 0 ? prev - 1 : 0);
          break;
        case 'Enter':
          e.preventDefault();
          if (filteredAgents[effectiveSelectedIndex]) {
            onSelect(filteredAgents[effectiveSelectedIndex].id);
          }
          break;
        case 'Escape':
          e.preventDefault();
          onClose();
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filteredAgents, effectiveSelectedIndex, onSelect, onClose]);

  // Scroll selected item into view
  useEffect(() => {
    const selectedElement = containerRef.current?.querySelector(`[data-index="${effectiveSelectedIndex}"]`);
    selectedElement?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [effectiveSelectedIndex]);

  if (!isOpen || filteredAgents.length === 0) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: 10, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 10, scale: 0.95 }}
        transition={{ duration: 0.15, ease: [0.4, 0, 0.2, 1] }}
        className="absolute bottom-full left-0 right-0 mb-2 z-50"
      >
        <div
          className="rounded-2xl overflow-hidden max-h-80 bg-white"
          style={{
            border: '1px solid #e8eaed',
            boxShadow: '0 8px 24px rgba(60, 64, 67, 0.16)',
          }}
        >
          {/* Header */}
          <div 
            className="px-3 py-2 border-b flex items-center justify-between"
            style={{ borderColor: '#e8eaed' }}
          >
            <span className="text-xs text-text-muted uppercase tracking-wider font-medium">
              Agents
            </span>
            <span className="text-xs text-text-muted">
              {filteredAgents.length} available
            </span>
          </div>

          {/* Agent List */}
          <div ref={containerRef} className="overflow-y-auto max-h-64 scrollbar-dark">
            {filteredAgents.map((agent, index) => {
              const Icon = iconMap[agent.icon] || Terminal;
              const isSelected = index === effectiveSelectedIndex;

              return (
                <motion.button
                  key={agent.id}
                  data-index={index}
                  onClick={() => onSelect(agent.id)}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`w-full text-left px-3 py-3 flex items-start gap-3 transition-all duration-150 ${
                    isSelected
                      ? 'bg-blue-50'
                      : 'hover:bg-bg-hover'
                  }`}
                  style={{
                    borderLeft: isSelected ? '2px solid #1a73e8' : '2px solid transparent',
                  }}
                >
                  {/* Icon */}
                  <div 
                    className={`w-9 h-9 rounded-2xl flex items-center justify-center flex-shrink-0 ${
                      isSelected ? 'bg-blue-100' : 'bg-slate-100'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${isSelected ? 'text-accent-blue' : 'text-text-secondary'}`} />
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`font-medium text-sm ${isSelected ? 'text-text-primary' : 'text-text-secondary'}`}>
                        {agent.name}
                      </span>
                      <span className="text-xs text-text-muted px-1.5 py-0.5 rounded-full bg-slate-100">
                        @{agent.id}
                      </span>
                    </div>
                    <p className="text-xs text-text-muted mt-0.5 line-clamp-2">
                      {agent.description}
                    </p>
                    
                    {/* Capabilities */}
                    <div className="flex flex-wrap gap-1 mt-2">
                      {agent.capabilities.slice(0, 3).map((cap, i) => (
                        <span 
                          key={i}
                          className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-100 text-text-muted"
                        >
                          {cap}
                        </span>
                      ))}
                      {agent.capabilities.length > 3 && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-100 text-text-muted">
                          +{agent.capabilities.length - 3}
                        </span>
                      )}
                    </div>
                  </div>
                </motion.button>
              );
            })}
          </div>

          {/* Footer - Keyboard hints */}
          <div 
            className="px-3 py-2 border-t flex items-center gap-4"
            style={{ borderColor: '#e8eaed' }}
          >
            <div className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 rounded bg-slate-100 text-[10px] text-text-muted">↑↓</kbd>
              <span className="text-[10px] text-text-muted">Navigate</span>
            </div>
            <div className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 rounded bg-slate-100 text-[10px] text-text-muted">Enter</kbd>
              <span className="text-[10px] text-text-muted">Select</span>
            </div>
            <div className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 rounded bg-slate-100 text-[10px] text-text-muted">Esc</kbd>
              <span className="text-[10px] text-text-muted">Close</span>
            </div>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

export default AgentPicker;
