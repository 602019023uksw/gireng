import { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, Copy } from 'lucide-react';
import Prism from 'prismjs';
import 'prismjs/components/prism-python';
import 'prismjs/components/prism-c';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-bash';

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
}

export function CodeBlock({ code, language = 'python', filename }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const highlighted = Prism.highlight(
    code,
    Prism.languages[language] || Prism.languages.plaintext,
    language
  );

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="rounded-xl overflow-hidden my-4"
      style={{
        background: 'rgba(10, 14, 28, 0.8)',
        border: '1px solid rgba(100, 120, 180, 0.15)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/5"
        style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
      >
        <span className="text-sm text-text-secondary capitalize">
          {filename || language}
        </span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2 py-1 rounded-md text-xs text-text-secondary hover:text-text-primary hover:bg-white/5 transition-all duration-150"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-accent-green" />
              <span className="text-accent-green">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Code */}
      <div className="overflow-x-auto">
        <pre className="p-4 text-sm font-mono leading-relaxed">
          <code
            dangerouslySetInnerHTML={{ __html: highlighted }}
            className={`language-${language}`}
          />
        </pre>
      </div>
    </motion.div>
  );
}

export default CodeBlock;
