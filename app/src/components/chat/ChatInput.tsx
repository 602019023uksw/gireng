import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Plus, Sparkles, SlidersHorizontal, Send } from 'lucide-react';
import { AgentPicker } from './AgentPicker';

interface ChatInputProps {
  onSend: (message: string, agentId?: string) => void;
  placeholder?: string;
}

export function ChatInput({ onSend, placeholder }: ChatInputProps) {
  const [message, setMessage] = useState('');
  const [isFocused, setIsFocused] = useState(false);
  const [showAgentPicker, setShowAgentPicker] = useState(false);
  const [agentSearchQuery, setAgentSearchQuery] = useState('');
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 200)}px`;
    }
  }, [message]);

  // Detect @ mention trigger
  useEffect(() => {
    const lastAtIndex = message.lastIndexOf('@');
    if (lastAtIndex !== -1) {
      const afterAt = message.slice(lastAtIndex + 1);
      // Check if we're in the middle of typing an agent mention
      // (no space after @ and not at end of another word)
      const hasSpaceAfter = afterAt.includes(' ');
      const isNewMention = lastAtIndex === 0 || message[lastAtIndex - 1] === ' ';
      
      if (!hasSpaceAfter && isNewMention) {
        setShowAgentPicker(true);
        setAgentSearchQuery(afterAt);
      } else {
        setShowAgentPicker(false);
      }
    } else {
      setShowAgentPicker(false);
    }
  }, [message]);

  // Close agent picker when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setShowAgentPicker(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSubmit = () => {
    if (message.trim()) {
      onSend(message.trim(), selectedAgentId || undefined);
      setMessage('');
      setSelectedAgentId(null);
      if (textareaRef.current) {
        textareaRef.current.style.height = 'auto';
      }
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Don't submit if agent picker is open (let it handle Enter)
    if (showAgentPicker && (e.key === 'Enter' || e.key === 'ArrowUp' || e.key === 'ArrowDown' || e.key === 'Escape')) {
      return;
    }
    
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleAgentSelect = (agentId: string) => {
    setSelectedAgentId(agentId);
    
    // Replace the @search with @agentId in the message
    const lastAtIndex = message.lastIndexOf('@');
    if (lastAtIndex !== -1) {
      const beforeAt = message.slice(0, lastAtIndex);
      const newMessage = beforeAt + `@${agentId} `;
      setMessage(newMessage);
    }
    
    setShowAgentPicker(false);
    textareaRef.current?.focus();
  };

  const handleAgentPickerClose = () => {
    setShowAgentPicker(false);
    // Remove the incomplete @mention
    const lastAtIndex = message.lastIndexOf('@');
    if (lastAtIndex !== -1) {
      const afterAt = message.slice(lastAtIndex + 1);
      if (!afterAt.includes(' ')) {
        setMessage(message.slice(0, lastAtIndex));
      }
    }
  };

  return (
    <div ref={containerRef} className="relative">
      {/* Agent Picker */}
      <AgentPicker
        isOpen={showAgentPicker}
        searchQuery={agentSearchQuery}
        onSelect={handleAgentSelect}
        onClose={handleAgentPickerClose}
      />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.2, ease: [0.4, 0, 0.2, 1] as const }}
        className="relative backdrop-blur-xl rounded-2xl transition-all duration-200"
        style={{
          background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.6) 0%, rgba(15, 20, 35, 0.4) 100%)',
          border: isFocused 
            ? '1px solid rgba(168, 85, 247, 0.5)' 
            : '1px solid rgba(100, 120, 180, 0.2)',
          boxShadow: isFocused 
            ? '0 0 0 3px rgba(168, 85, 247, 0.1), 0 4px 24px -1px rgba(0, 0, 0, 0.3)' 
            : '0 4px 24px -1px rgba(0, 0, 0, 0.25)',
        }}
      >
        {/* Selected Agent Indicator */}
        {selectedAgentId && (
          <div className="px-4 pt-3 flex items-center gap-2">
            <span className="text-xs text-text-muted">Using agent:</span>
            <span 
              className="text-xs px-2 py-0.5 rounded-full bg-accent-purple/20 text-accent-purple border border-accent-purple/30"
            >
              @{selectedAgentId}
            </span>
            <button 
              onClick={() => setSelectedAgentId(null)}
              className="text-xs text-text-muted hover:text-text-primary"
            >
              ✕
            </button>
          </div>
        )}

        <textarea
          ref={textareaRef}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder || "What do you want to do? Type '@' to mention an agent, '#' to mention a knowledge, or '/' to quickly access to prompts."}
          className="w-full bg-transparent text-text-primary placeholder:text-text-muted px-4 py-3 pr-12 resize-none outline-none min-h-[80px] max-h-[200px]"
          rows={1}
        />

        {/* Input Actions */}
        <div className="flex items-center justify-between px-3 pb-3">
          <div className="flex items-center gap-1">
            <button
              className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary transition-all duration-150 hover:bg-white/5"
              title="Add attachment"
            >
              <Plus className="w-4 h-4" />
            </button>
            <button
              className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-text-secondary hover:text-text-primary transition-all duration-150 hover:bg-white/5"
              title="Model settings"
            >
              <Sparkles className="w-4 h-4" />
              <span className="text-xs">8</span>
            </button>
            <button
              className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary transition-all duration-150 hover:bg-white/5"
              title="Filter"
            >
              <SlidersHorizontal className="w-4 h-4" />
            </button>
          </div>

          <button
            onClick={handleSubmit}
            disabled={!message.trim()}
            className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all duration-150 ${
              message.trim()
                ? 'text-accent-purple hover:bg-accent-purple/10'
                : 'text-text-muted cursor-not-allowed'
            }`}
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </motion.div>
    </div>
  );
}

export default ChatInput;
