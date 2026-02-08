import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Sparkles, ChevronDown, Check, Zap, Cpu, Globe } from 'lucide-react';

interface Model {
  id: string;
  name: string;
  description: string;
  icon: 'sparkle' | 'zap' | 'cpu' | 'globe';
  provider: string;
}

interface ModelSelectorProps {
  selectedModelId: string;
  onSelect: (modelId: string) => void;
}

const models: Model[] = [
  { 
    id: 'gemini-2.5-pro', 
    name: 'Gemini 2.5 Pro', 
    description: 'Best for complex tasks',
    icon: 'sparkle',
    provider: 'Google'
  },
  { 
    id: 'gemini-2.5-flash', 
    name: 'Gemini 2.5 Flash', 
    description: 'Fast and efficient',
    icon: 'zap',
    provider: 'Google'
  },
  { 
    id: 'claude-3-opus', 
    name: 'Claude 3 Opus', 
    description: 'Advanced reasoning',
    icon: 'sparkle',
    provider: 'Anthropic'
  },
  { 
    id: 'claude-3-sonnet', 
    name: 'Claude 3.5 Sonnet', 
    description: 'Balanced performance',
    icon: 'zap',
    provider: 'Anthropic'
  },
  { 
    id: 'gpt-4o', 
    name: 'GPT-4o', 
    description: 'Multimodal capabilities',
    icon: 'sparkle',
    provider: 'OpenAI'
  },
  { 
    id: 'gpt-4o-mini', 
    name: 'GPT-4o Mini', 
    description: 'Cost-effective',
    icon: 'zap',
    provider: 'OpenAI'
  },
  { 
    id: 'qwen3-30b', 
    name: 'Qwen3 30b A3B', 
    description: 'Open source model',
    icon: 'cpu',
    provider: 'Alibaba'
  },
  { 
    id: 'cisco-sec', 
    name: 'Cisco Foundation Sec 8b', 
    description: 'Security-focused',
    icon: 'globe',
    provider: 'Cisco'
  },
];

const iconMap = {
  sparkle: Sparkles,
  zap: Zap,
  cpu: Cpu,
  globe: Globe,
};

export function ModelSelector({ selectedModelId, onSelect }: ModelSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const selectedModel = models.find(m => m.id === selectedModelId) || models[0];
  const SelectedIcon = iconMap[selectedModel.icon];
  
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
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-all duration-150 hover:bg-white/5"
        style={{
          background: 'rgba(20, 28, 50, 0.5)',
          border: '1px solid rgba(100, 120, 180, 0.2)',
        }}
      >
        <SelectedIcon className="w-4 h-4 text-accent-blue" />
        <span className="text-text-primary">{selectedModel.name}</span>
        <ChevronDown className={`w-3.5 h-3.5 text-text-secondary transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="absolute top-full left-0 mt-2 w-72 rounded-xl overflow-hidden z-50"
            style={{
              background: 'rgba(15, 22, 40, 0.98)',
              backdropFilter: 'blur(16px)',
              border: '1px solid rgba(100, 120, 180, 0.2)',
              boxShadow: '0 8px 32px -4px rgba(0, 0, 0, 0.5)',
            }}
          >
            <div className="py-2">
              <p className="px-3 py-2 text-xs text-text-muted uppercase tracking-wider">
                Select Model
              </p>
              
              {/* Google Models */}
              <div className="px-2 pb-2">
                <p className="px-2 py-1 text-xs text-text-muted">Google</p>
                {models.filter(m => m.provider === 'Google').map((model) => {
                  const Icon = iconMap[model.icon];
                  return (
                    <button
                      key={model.id}
                      onClick={() => {
                        onSelect(model.id);
                        setIsOpen(false);
                      }}
                      className="w-full flex items-center gap-3 px-2 py-2 rounded-lg text-left transition-all duration-150 hover:bg-white/5"
                    >
                      <div className="w-5 flex justify-center">
                        {model.id === selectedModelId ? (
                          <Check className="w-4 h-4 text-accent-blue" />
                        ) : (
                          <Icon className="w-4 h-4 text-text-secondary" />
                        )}
                      </div>
                      <div>
                        <p className={`text-sm font-medium ${
                          model.id === selectedModelId ? 'text-accent-blue' : 'text-text-primary'
                        }`}>
                          {model.name}
                        </p>
                        <p className="text-xs text-text-muted">{model.description}</p>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Anthropic Models */}
              <div className="px-2 py-2 border-t border-white/5" style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}>
                <p className="px-2 py-1 text-xs text-text-muted">Anthropic</p>
                {models.filter(m => m.provider === 'Anthropic').map((model) => {
                  const Icon = iconMap[model.icon];
                  return (
                    <button
                      key={model.id}
                      onClick={() => {
                        onSelect(model.id);
                        setIsOpen(false);
                      }}
                      className="w-full flex items-center gap-3 px-2 py-2 rounded-lg text-left transition-all duration-150 hover:bg-white/5"
                    >
                      <div className="w-5 flex justify-center">
                        {model.id === selectedModelId ? (
                          <Check className="w-4 h-4 text-accent-blue" />
                        ) : (
                          <Icon className="w-4 h-4 text-text-secondary" />
                        )}
                      </div>
                      <div>
                        <p className={`text-sm font-medium ${
                          model.id === selectedModelId ? 'text-accent-blue' : 'text-text-primary'
                        }`}>
                          {model.name}
                        </p>
                        <p className="text-xs text-text-muted">{model.description}</p>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* OpenAI Models */}
              <div className="px-2 py-2 border-t border-white/5" style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}>
                <p className="px-2 py-1 text-xs text-text-muted">OpenAI</p>
                {models.filter(m => m.provider === 'OpenAI').map((model) => {
                  const Icon = iconMap[model.icon];
                  return (
                    <button
                      key={model.id}
                      onClick={() => {
                        onSelect(model.id);
                        setIsOpen(false);
                      }}
                      className="w-full flex items-center gap-3 px-2 py-2 rounded-lg text-left transition-all duration-150 hover:bg-white/5"
                    >
                      <div className="w-5 flex justify-center">
                        {model.id === selectedModelId ? (
                          <Check className="w-4 h-4 text-accent-blue" />
                        ) : (
                          <Icon className="w-4 h-4 text-text-secondary" />
                        )}
                      </div>
                      <div>
                        <p className={`text-sm font-medium ${
                          model.id === selectedModelId ? 'text-accent-blue' : 'text-text-primary'
                        }`}>
                          {model.name}
                        </p>
                        <p className="text-xs text-text-muted">{model.description}</p>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Other Models */}
              <div className="px-2 pt-2 border-t border-white/5" style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}>
                <p className="px-2 py-1 text-xs text-text-muted">Others</p>
                {models.filter(m => !['Google', 'Anthropic', 'OpenAI'].includes(m.provider)).map((model) => {
                  const Icon = iconMap[model.icon];
                  return (
                    <button
                      key={model.id}
                      onClick={() => {
                        onSelect(model.id);
                        setIsOpen(false);
                      }}
                      className="w-full flex items-center gap-3 px-2 py-2 rounded-lg text-left transition-all duration-150 hover:bg-white/5"
                    >
                      <div className="w-5 flex justify-center">
                        {model.id === selectedModelId ? (
                          <Check className="w-4 h-4 text-accent-blue" />
                        ) : (
                          <Icon className="w-4 h-4 text-text-secondary" />
                        )}
                      </div>
                      <div>
                        <p className={`text-sm font-medium ${
                          model.id === selectedModelId ? 'text-accent-blue' : 'text-text-primary'
                        }`}>
                          {model.name}
                        </p>
                        <p className="text-xs text-text-muted">{model.description}</p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default ModelSelector;
