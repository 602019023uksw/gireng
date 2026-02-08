import { motion } from 'framer-motion';
import { Sparkles, Clock, Bot } from 'lucide-react';
import type { Message } from '@/types';
import { ToolCallCard } from './ToolCallCard';
import { CodeBlock } from './CodeBlock';
import { AnalysisCompletedCard } from './AnalysisCompletedCard';
import { getAgentById } from '@/agents/ghidra-agent';

interface MessageBubbleProps {
  message: Message;
  onViewAnalysis?: () => void;
}

export function MessageBubble({ message, onViewAnalysis }: MessageBubbleProps) {
  const formatTime = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m`;
    if (hours < 24) return `${hours}h`;
    return date.toLocaleDateString();
  };

  // Parse markdown-like content
  const renderContent = (content: string) => {
    const lines = content.split('\n');
    const elements: React.ReactNode[] = [];
    let currentList: string[] = [];

    const flushList = () => {
      if (currentList.length > 0) {
        elements.push(
          <ul key={`list-${elements.length}`} className="list-disc list-inside mb-3 space-y-1">
            {currentList.map((item, i) => (
              <li key={i} className="text-sm text-text-secondary">{item.replace(/^•\s*/, '')}</li>
            ))}
          </ul>
        );
        currentList = [];
      }
    };

    lines.forEach((line, index) => {
      // Headers
      if (line.startsWith('## ')) {
        flushList();
        elements.push(
          <h2 key={`h2-${index}`} className="text-lg font-semibold text-text-primary mt-4 mb-2">
            {line.replace('## ', '')}
          </h2>
        );
        return;
      }
      if (line.startsWith('### ')) {
        flushList();
        elements.push(
          <h3 key={`h3-${index}`} className="text-base font-semibold text-text-primary mt-3 mb-2">
            {line.replace('### ', '')}
          </h3>
        );
        return;
      }

      // List items
      if (line.startsWith('• ') || line.startsWith('- ')) {
        currentList.push(line);
        return;
      }

      // Empty line - flush list
      if (line.trim() === '') {
        flushList();
        return;
      }

      // Regular paragraph with inline code
      flushList();
      const parts = line.split(/(`[^`]+`)/g);
      elements.push(
        <p key={`p-${index}`} className="text-sm text-text-secondary leading-relaxed mb-2">
          {parts.map((part, i) => {
            if (part.startsWith('`') && part.endsWith('`')) {
              return (
                <code 
                  key={i}
                  className="px-1.5 py-0.5 rounded text-xs font-mono"
                  style={{
                    background: 'rgba(88, 166, 255, 0.1)',
                    border: '1px solid rgba(88, 166, 255, 0.2)',
                    color: '#F0F6FC',
                  }}
                >
                  {part.slice(1, -1)}
                </code>
              );
            }
            return part;
          })}
        </p>
      );
    });

    flushList();
    return elements;
  };

  if (message.isUser) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
        className="flex justify-end mb-4"
      >
        <div 
          className="max-w-[80%] rounded-2xl rounded-tr-sm px-4 py-3"
          style={{
            background: 'linear-gradient(135deg, rgba(35, 45, 75, 0.6) 0%, rgba(25, 32, 55, 0.5) 100%)',
            border: '1px solid rgba(100, 120, 180, 0.2)',
            backdropFilter: 'blur(8px)',
          }}
        >
          <p className="text-text-primary text-sm whitespace-pre-wrap">{message.content}</p>
        </div>
      </motion.div>
    );
  }

  // Get agent info if this message was triggered by an agent mention
  const agent = message.agentId ? getAgentById(message.agentId) : null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
      className="flex gap-3 mb-4"
    >
      {/* AI Avatar */}
      <div 
        className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 mt-1"
        style={{
          background: agent 
            ? 'linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(168, 85, 247, 0.05) 100%)'
            : 'linear-gradient(135deg, rgba(88, 166, 255, 0.2) 0%, rgba(88, 166, 255, 0.05) 100%)',
          border: agent 
            ? '1px solid rgba(168, 85, 247, 0.3)'
            : '1px solid rgba(88, 166, 255, 0.3)',
        }}
      >
        {agent ? (
          <Bot className="w-3.5 h-3.5 text-accent-purple" />
        ) : (
          <Sparkles className="w-3.5 h-3.5 text-accent-blue" />
        )}
      </div>

      <div className="flex-1 max-w-[85%]">
        {/* Message Header */}
        <div className="flex items-center gap-2 mb-1">
          {/* Agent Badge */}
          {agent && (
            <span 
              className="text-xs px-2 py-0.5 rounded-full flex items-center gap-1"
              style={{
                background: 'rgba(168, 85, 247, 0.15)',
                border: '1px solid rgba(168, 85, 247, 0.25)',
                color: '#a855f7',
              }}
            >
              <Bot className="w-3 h-3" />
              {agent.name}
            </span>
          )}
          <Clock className="w-3.5 h-3.5 text-text-muted" />
          <span className="text-xs text-text-muted">{formatTime(message.timestamp)}</span>
        </div>
        
        {/* Render parsed content */}
        <div className="mb-3">
          {renderContent(message.content)}
        </div>

        {/* Tool Calls */}
        {message.toolCalls?.map((tool) => (
          <ToolCallCard key={tool.id} tool={tool} />
        ))}

        {/* Analysis Completed Card */}
        {message.showAnalysisCompleted && (
          <AnalysisCompletedCard
            fileHash="9910d401d6354b7681b3c1b121960ac847e3642f734fa51bc9eefcd4900f89ec"
            progress={7}
            maxProgress={7}
            onViewMore={onViewAnalysis}
          />
        )}

        {/* Code Blocks */}
        {message.codeBlocks?.map((block) => (
          <CodeBlock
            key={block.id}
            code={block.code}
            language={block.language}
            filename={block.filename}
          />
        ))}
      </div>
    </motion.div>
  );
}

export default MessageBubble;
