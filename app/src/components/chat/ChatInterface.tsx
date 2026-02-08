import { useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import type { Message } from '@/types';

interface ChatInterfaceProps {
  messages: Message[];
  onSendMessage: (message: string, agentId?: string) => void;
  onViewAnalysis?: () => void;
}

export function ChatInterface({ messages, onSendMessage, onViewAnalysis }: ChatInterfaceProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  return (
    <div className="flex flex-col h-full">
      {/* Messages Area */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto scrollbar-dark px-4 py-6 pb-32"
      >
        <div className="max-w-3xl mx-auto">
          {messages.map((message) => (
            <MessageBubble
              key={message.id}
              message={message}
              onViewAnalysis={onViewAnalysis}
            />
          ))}
        </div>
      </div>

      {/* Input Area - Fixed at bottom */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] as const }}
        className="absolute bottom-0 left-0 right-0 border-t border-white/10 bg-bg-primary/90 backdrop-blur-xl px-4 py-4 z-50"
        style={{ borderColor: 'rgba(100, 120, 180, 0.12)' }}
      >
        <div className="max-w-3xl mx-auto">
          <ChatInput onSend={(msg, agentId) => onSendMessage(msg, agentId)} />
        </div>
      </motion.div>
    </div>
  );
}

export default ChatInterface;
