import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bot, ChevronDown, Check } from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  description: string;
  icon: string;
}

interface AgentSelectorProps {
  selectedAgentId: string;
  onSelect: (agentId: string) => void;
}

const agents: Agent[] = [
  { id: 'default', name: 'Default Agent', description: 'General purpose AI assistant', icon: 'bot' },
  { id: 'virustotal', name: 'VirusTotal Agent', description: 'Analyze files with VirusTotal', icon: 'shield' },
  { id: 'ghidra', name: 'Ghidra Agent', description: 'Reverse engineering with Ghidra', icon: 'code' },
  { id: 'ida-pro', name: 'IDA Pro Agent', description: 'Advanced binary analysis', icon: 'cpu' },
  { id: 'radare', name: 'Radare Agent', description: 'Open source reverse engineering', icon: 'terminal' },
  { id: 'clamav', name: 'ClamAV Agent', description: 'Antivirus scanning', icon: 'scan' },
];

export function AgentSelector({ selectedAgentId, onSelect }: AgentSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const selectedAgent = agents.find(a => a.id === selectedAgentId) || agents[0];
  
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div ref={dropdownRef} className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-all duration-150"
        style={{
          background: 'rgba(20, 28, 50, 0.5)',
          border: '1px solid rgba(100, 120, 180, 0.2)',
          color: '#A0A8B8',
        }}
      >
        <Bot className="w-4 h-4" />
        <span>{selectedAgent.name}</span>
        <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="absolute top-full left-0 mt-2 w-64 rounded-xl overflow-hidden z-50"
            style={{
              background: 'rgba(15, 22, 40, 0.95)',
              backdropFilter: 'blur(16px)',
              border: '1px solid rgba(100, 120, 180, 0.2)',
              boxShadow: '0 8px 32px -4px rgba(0, 0, 0, 0.5)',
            }}
          >
            <div className="py-2">
              <p className="px-3 py-2 text-xs text-text-muted uppercase tracking-wider">
                Select Agent
              </p>
              {agents.map((agent) => (
                <button
                  key={agent.id}
                  onClick={() => {
                    onSelect(agent.id);
                    setIsOpen(false);
                  }}
                  className="w-full flex items-start gap-3 px-3 py-2.5 text-left transition-all duration-150 hover:bg-white/5"
                >
                  <div className="mt-0.5">
                    {agent.id === selectedAgentId ? (
                      <Check className="w-4 h-4 text-accent-blue" />
                    ) : (
                      <div className="w-4 h-4" />
                    )}
                  </div>
                  <div>
                    <p className={`text-sm font-medium ${
                      agent.id === selectedAgentId ? 'text-accent-blue' : 'text-text-primary'
                    }`}>
                      {agent.name}
                    </p>
                    <p className="text-xs text-text-muted mt-0.5">
                      {agent.description}
                    </p>
                  </div>
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default AgentSelector;
