import { useState, useRef, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Upload } from 'lucide-react';
import { ModelSelector } from './ModelSelector';
import { ChatInput } from './ChatInput';
import { QuickActionChips } from './QuickActionChips';
import type { QuickAction } from '@/types';

interface WelcomeScreenProps {
  userName?: string;
  selectedModelId: string;
  quickActions: QuickAction[];
  onModelSelect: (modelId: string) => void;
  onSendMessage: (message: string) => void;
  onQuickAction?: (actionId: string) => void;
  onFileUpload?: (file: File) => void;
}

export function WelcomeScreen({
  userName,
  selectedModelId,
  quickActions,
  onModelSelect,
  onSendMessage,
  onQuickAction,
  onFileUpload,
}: WelcomeScreenProps) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && onFileUpload) onFileUpload(file);
  }, [onFileUpload]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && onFileUpload) onFileUpload(file);
  }, [onFileUpload]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] as const }}
      className="flex flex-col items-center justify-center h-full px-4 py-8 overflow-y-auto"
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
    >
      {/* Drag overlay */}
      {isDragging && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-bg-primary/80 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-3 p-8 border-2 border-dashed border-accent-purple rounded-2xl">
            <Upload className="w-12 h-12 text-accent-purple" />
            <p className="text-lg text-text-primary">Drop binary file to analyze</p>
          </div>
        </div>
      )}

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        onChange={handleFileChange}
      />

      {/* Model Selector */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.1 }}
        className="absolute top-4 left-1/2 -translate-x-1/2"
      >
        <ModelSelector
          selectedModelId={selectedModelId}
          onSelect={onModelSelect}
        />
      </motion.div>

      {/* Welcome Message */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.15, ease: [0.4, 0, 0.2, 1] as const }}
        className="text-center mb-8"
      >
        <h1 className="text-4xl font-semibold text-text-primary">
          {userName ? (
            <>Welcome, <span className="text-accent-purple">{userName}</span></>
          ) : (
            'Welcome to IrengSec'
          )}
        </h1>
        <p className="mt-2 text-text-secondary">
          AI-powered malware analysis and reverse engineering
        </p>
      </motion.div>

      {/* Upload Drop Zone */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.18, ease: [0.4, 0, 0.2, 1] as const }}
        className="w-full max-w-2xl mb-6"
      >
        <button
          onClick={() => fileInputRef.current?.click()}
          className="w-full flex items-center justify-center gap-3 px-6 py-4 border border-dashed border-border-default rounded-xl hover:border-accent-purple/50 hover:bg-accent-purple/5 transition-all duration-200 group"
        >
          <Upload className="w-5 h-5 text-text-muted group-hover:text-accent-purple transition-colors" />
          <span className="text-text-secondary group-hover:text-text-primary transition-colors">
            Upload a binary file to analyze, or drag and drop
          </span>
        </button>
      </motion.div>

      {/* Input Area */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.2, ease: [0.4, 0, 0.2, 1] as const }}
        className="w-full max-w-2xl"
      >
        <ChatInput onSend={onSendMessage} />
      </motion.div>

      {/* Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.25, ease: [0.4, 0, 0.2, 1] as const }}
        className="w-full max-w-2xl mt-4"
      >
        <QuickActionChips actions={quickActions} onActionClick={onQuickAction} />
      </motion.div>
    </motion.div>
  );
}

export default WelcomeScreen;
