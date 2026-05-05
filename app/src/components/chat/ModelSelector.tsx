import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Cpu, ChevronDown, Check } from 'lucide-react';
import { getModels } from '@/lib/api';

interface ApiModel {
  id: string;
  name: string;
  icon?: string;
  type?: string;
  isSelected?: boolean;
}

interface ModelSelectorProps {
  selectedModelId: string;
  onSelect: (modelId: string) => void;
}

export function ModelSelector({ selectedModelId, onSelect }: ModelSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [models, setModels] = useState<ApiModel[]>([]);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Fetch available models from the API on mount
  useEffect(() => {
    let cancelled = false;
    getModels().then((data: ApiModel[]) => {
      if (!cancelled && data.length > 0) {
        setModels(data);
        // Auto-select the first (or marked) model if current selection not in list
        const hasSelected = data.some((m: ApiModel) => m.id === selectedModelId);
        if (!hasSelected) {
          const preferred = data.find((m: ApiModel) => m.isSelected) || data[0];
          onSelect(preferred.id);
        }
      }
    }).catch(() => { /* ignore */ });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const selectedModel = models.find(m => m.id === selectedModelId) || models[0];
  const displayName = selectedModel?.name || selectedModelId;

  // If only one model (or none loaded yet), show as a simple badge (no dropdown)
  if (models.length <= 1) {
    return (
      <div className="flex items-center gap-2 px-4 py-2 rounded-full text-sm"
        style={{
          background: '#ffffff',
          border: '1px solid #dadce0',
          boxShadow: '0 1px 2px rgba(60, 64, 67, 0.10)',
        }}
      >
        <Cpu className="w-4 h-4 text-accent-blue" />
        <span className="text-text-primary">{displayName}</span>
      </div>
    );
  }

  return (
    <div ref={dropdownRef} className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 rounded-full text-sm transition-all duration-150 hover:bg-bg-hover"
        style={{
          background: '#ffffff',
          border: '1px solid #dadce0',
          boxShadow: '0 1px 2px rgba(60, 64, 67, 0.10)',
        }}
      >
        <Cpu className="w-4 h-4 text-accent-blue" />
        <span className="text-text-primary">{displayName}</span>
        <ChevronDown className={`w-3.5 h-3.5 text-text-secondary transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="absolute top-full left-0 mt-2 w-64 rounded-2xl overflow-hidden z-50"
            style={{
              background: '#ffffff',
              border: '1px solid #e8eaed',
              boxShadow: '0 8px 24px rgba(60, 64, 67, 0.16)',
            }}
          >
            <div className="py-2">
              <p className="px-3 py-2 text-xs text-text-muted uppercase tracking-wider">
                Select Model
              </p>
              <div className="px-2">
                {models.map((model) => (
                  <button
                    key={model.id}
                    onClick={() => {
                      onSelect(model.id);
                      setIsOpen(false);
                    }}
                    className="w-full flex items-center gap-3 px-2 py-2 rounded-xl text-left transition-all duration-150 hover:bg-bg-hover"
                  >
                    <div className="w-5 flex justify-center">
                      {model.id === selectedModelId ? (
                        <Check className="w-4 h-4 text-accent-blue" />
                      ) : (
                        <Cpu className="w-4 h-4 text-text-secondary" />
                      )}
                    </div>
                    <p className={`text-sm font-medium ${
                      model.id === selectedModelId ? 'text-accent-blue' : 'text-text-primary'
                    }`}>
                      {model.name}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default ModelSelector;
