import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Send } from 'lucide-react';
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

  const updateMentionState = (nextMessage: string) => {
    const lastAtIndex = nextMessage.lastIndexOf('@');
    if (lastAtIndex === -1) {
      setShowAgentPicker(false);
      setAgentSearchQuery('');
      return;
    }
    const afterAt = nextMessage.slice(lastAtIndex + 1);
    const hasSpaceAfter = afterAt.includes(' ');
    const isNewMention = lastAtIndex === 0 || nextMessage[lastAtIndex - 1] === ' ';
    if (!hasSpaceAfter && isNewMention) {
      setShowAgentPicker(true);
      setAgentSearchQuery(afterAt);
      return;
    }
    setShowAgentPicker(false);
    setAgentSearchQuery('');
  };

  const handleMessageChange = (nextMessage: string) => {
    setMessage(nextMessage);
    updateMentionState(nextMessage);
  };

  const handleSubmit = () => {
    if (message.trim()) {
      onSend(message.trim(), selectedAgentId || undefined);
      setMessage('');
      setSelectedAgentId(null);
      setShowAgentPicker(false);
      setAgentSearchQuery('');
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
      updateMentionState(newMessage);
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
        const nextMessage = message.slice(0, lastAtIndex);
        setMessage(nextMessage);
        updateMentionState(nextMessage);
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
        className="relative rounded-3xl transition-all duration-200 bg-white"
        style={{
          border: isFocused
            ? '1px solid #1a73e8'
            : '1px solid #dadce0',
          boxShadow: isFocused
            ? '0 0 0 4px rgba(26, 115, 232, 0.14), 0 8px 24px rgba(60, 64, 67, 0.12)'
            : '0 1px 3px rgba(60, 64, 67, 0.16), 0 1px 2px rgba(60, 64, 67, 0.08)',
        }}
      >
        {/* Selected Agent Indicator */}
        {selectedAgentId && (
          <div className="px-4 pt-3 flex items-center gap-2">
            <span className="text-xs text-text-muted">Using agent:</span>
            <span 
              className="text-xs px-2 py-0.5 rounded-full bg-blue-50 text-accent-blue border border-blue-100"
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
          onChange={(e) => handleMessageChange(e.target.value)}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder || "What do you want to do? Type '@' to mention an agent, '#' to mention a knowledge, or '/' to quickly access to prompts."}
          className="w-full bg-transparent text-text-primary placeholder:text-text-muted px-4 py-3 pr-12 resize-none outline-none min-h-[80px] max-h-[200px]"
          rows={1}
        />

        {/* Input Actions */}
        <div className="flex items-center justify-end px-3 pb-3">
          <button
            onClick={handleSubmit}
            disabled={!message.trim()}
            className={`w-9 h-9 rounded-full flex items-center justify-center transition-all duration-150 ${
              message.trim()
                ? 'text-white bg-accent-blue hover:bg-[#1557b0] shadow-glass'
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
