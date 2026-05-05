import { motion } from 'framer-motion';
import { X, FileCode } from 'lucide-react';
import Prism from 'prismjs';
import 'prismjs/components/prism-c';
import 'prismjs/components/prism-python';

interface CodeFile {
  id: string;
  name: string;
  language: string;
  content: string;
}

interface CodeViewerProps {
  files: CodeFile[];
  activeFileId: string;
  onClose: () => void;
  onFileChange: (fileId: string) => void;
}

export function CodeViewer({ files, activeFileId, onClose, onFileChange }: CodeViewerProps) {
  const activeFile = files.find(f => f.id === activeFileId) || files[0];

  const highlighted = activeFile ? Prism.highlight(
    activeFile.content,
    Prism.languages[activeFile.language] || Prism.languages.plaintext,
    activeFile.language
  ) : '';

  const lines = activeFile?.content.split('\n') || [];

  return (
    <motion.div
      initial={{ opacity: 0, x: 50 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 50 }}
      transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
      className="w-[500px] h-screen flex flex-col"
      style={{
        background: '#ffffff',
        borderLeft: '1px solid #e8eaed',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b"
        style={{ borderColor: '#e8eaed' }}
      >
        <div className="flex items-center gap-2">
          <FileCode className="w-5 h-5 text-text-secondary" />
          <span className="text-sm font-medium text-text-primary">Resources</span>
        </div>
        <div className="flex items-center gap-2">
          {/* File tabs */}
          <div className="flex items-center gap-1">
            {files.map((file) => (
              <button
                key={file.id}
                onClick={() => onFileChange(file.id)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-150 ${
                  file.id === activeFileId
                    ? 'text-accent-blue'
                    : 'text-text-secondary hover:text-text-primary'
                }`}
                style={{
                  background: file.id === activeFileId
                    ? '#e8f0fe'
                    : 'transparent',
                  border: file.id === activeFileId
                    ? '1px solid #d2e3fc'
                    : '1px solid transparent',
                }}
              >
                {file.name.length > 15 ? file.name.substring(0, 12) + '...' : file.name}
              </button>
            ))}
          </div>
          <button
            onClick={onClose}
            className="w-7 h-7 rounded-full flex items-center justify-center text-text-secondary hover:text-accent-blue hover:bg-bg-hover transition-all duration-150"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Code Content */}
      <div className="flex-1 overflow-auto scrollbar-dark">
        <div className="flex">
          {/* Line Numbers */}
          <div 
            className="py-4 px-3 text-right select-none"
            style={{
              background: '#f8fafd',
              borderRight: '1px solid #e8eaed',
            }}
          >
            {lines.map((_, i) => (
              <div
                key={i}
                className="text-xs text-text-muted leading-6"
              >
                {i + 1}
              </div>
            ))}
          </div>

          {/* Code */}
          <div className="flex-1 py-4 px-4">
            <pre className="text-sm font-mono leading-6">
              <code
                dangerouslySetInnerHTML={{ __html: highlighted }}
                className={`language-${activeFile?.language || 'text'}`}
              />
            </pre>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export default CodeViewer;
