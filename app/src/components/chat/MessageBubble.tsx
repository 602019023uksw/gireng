import { motion } from 'framer-motion';
import { Sparkles, Clock, Bot } from 'lucide-react';
import type { Message } from '@/types';
import { ToolCallCard } from './ToolCallCard';
import { CodeBlock } from './CodeBlock';
import { AnalysisCompletedCard } from './AnalysisCompletedCard';
import { getAgentById } from '@/agents/ghidra-agent';
import { MarkdownContent } from '@/components/common/MarkdownContent';

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

  if (message.isUser) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
        className="flex justify-end mb-5"
      >
        <div
          className="max-w-[80%] rounded-3xl rounded-tr-lg px-5 py-3"
          style={{
            background: '#e8f0fe',
            border: '1px solid #d2e3fc',
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
      className="flex gap-4 mb-6"
    >
      {/* AI Avatar */}
      <div
        className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 mt-1"
        style={{
          background: agent
            ? '#f3e8fd'
            : '#e8f0fe',
          border: agent
            ? '1px solid #e9d2fd'
            : '1px solid #d2e3fc',
        }}
      >
        {agent ? (
          <Bot className="w-4 h-4 text-accent-purple" />
        ) : (
          <Sparkles className="w-4 h-4 text-accent-blue" />
        )}
      </div>

      <div className="flex-1 max-w-[85%]">
        {/* Message Header */}
        <div className="flex items-center gap-2 mb-1">
          {/* Agent Badge */}
          {agent && (
            <span
              className="text-xs px-2.5 py-1 rounded-full flex items-center gap-1"
              style={{
                background: '#f3e8fd',
                border: '1px solid #e9d2fd',
                color: '#6750a4',
              }}
            >
              <Bot className="w-3 h-3" />
              {agent.name}
            </span>
          )}
          <Clock className="w-3.5 h-3.5 text-text-muted" />
          <span className="text-xs text-text-muted">{formatTime(message.timestamp)}</span>
        </div>

        {/* Analysis Completed Card */}
        {message.showAnalysisCompleted && (
          <AnalysisCompletedCard
            fileHash={message.analysisHash || ''}
            progress={message.analyzerCount || 0}
            maxProgress={message.analyzerTotal || 0}
            onViewMore={onViewAnalysis}
          />
        )}

        {/* Render markdown content */}
        <div className="mb-3">
          <MarkdownContent content={message.content} compact />
        </div>

        {/* Tool Calls */}
        {message.toolCalls?.map((tool) => (
          <ToolCallCard key={tool.id} tool={tool} />
        ))}

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
