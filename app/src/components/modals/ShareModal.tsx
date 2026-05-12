import { motion, AnimatePresence } from 'framer-motion';
import { X, Copy, Check } from 'lucide-react';
import { useState } from 'react';

interface ShareModalProps {
  isOpen: boolean;
  onClose: () => void;
  chatTitle?: string;
}

export function ShareModal({ isOpen, onClose, chatTitle = 'VirusTotal File Analysis' }: ShareModalProps) {
  const [copied, setCopied] = useState(false);
  const shareUrl = 'https://github.com/danilchristianto/gireng';

  const handleCopy = () => {
    navigator.clipboard.writeText(shareUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            onClick={onClose}
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
            className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg z-50"
          >
            <div
              className="rounded-3xl bg-white p-6"
              style={{
                border: '1px solid #e8eaed',
                boxShadow: '0 24px 48px rgba(60, 64, 67, 0.20)',
              }}
            >
              {/* Header */}
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-text-primary">
                  Share Chat {chatTitle}
                </h2>
                <button
                  onClick={onClose}
                  className="w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-accent-blue hover:bg-bg-hover transition-all duration-150"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Description */}
              <p className="text-sm text-text-secondary mb-6">
                Create a shareable URL that others can use to import this chat directly. 
                Every message you send after creating the URL will remain private.
              </p>

              {/* URL Input */}
              <div className="flex items-center gap-3 mb-6">
                <div
                  className="flex-1 px-4 py-3 rounded-xl font-mono text-sm text-text-secondary truncate"
                  style={{
                    background: '#f8fafd',
                    border: '1px solid #e8eaed',
                  }}
                >
                  {shareUrl}
                </div>
              </div>

              {/* Create URL Button */}
              <button
                onClick={handleCopy}
                className="w-full py-3 px-4 rounded-full font-medium text-sm transition-all duration-150 flex items-center justify-center gap-2"
                style={{
                  background: '#e8f0fe',
                  border: '1px solid #d2e3fc',
                  color: '#1a73e8',
                }}
              >
                {copied ? (
                  <>
                    <Check className="w-4 h-4" />
                    <span>Copied to Clipboard</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-4 h-4" />
                    <span>Create URL</span>
                  </>
                )}
              </button>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

export default ShareModal;
