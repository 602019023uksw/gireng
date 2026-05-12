import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface MarkdownContentProps {
  content: string;
  compact?: boolean;
  className?: string;
}

function normalizeMarkdown(content: string): string {
  let normalized = content
    .replace(/\r\n/g, '\n')
    .replace(/\u2022/g, '- ')
    .replace(/â€¢/g, '- ')
    .replace(/\u2192/g, '->')
    .replace(/â†’/g, '->')
    .replace(/â€”/g, '--')
    .replace(/\u00A0/g, ' ')
    .trim();

  const lines = normalized.split('\n');
  const summaryIndex = lines.findIndex((line) => /^##\s+Summary\s*$/i.test(line.trim()));
  if (summaryIndex > 0) {
    const title = lines.slice(0, summaryIndex).join('\n').trim();
    const rest = lines.slice(summaryIndex).join('\n').trim();
    normalized = `${title}\n\n---\n\n${rest}`;
  }

  return normalized;
}

export function MarkdownContent({ content, compact = false, className = '' }: MarkdownContentProps) {
  const markdown = normalizeMarkdown(content);
  const paragraphClass = compact
    ? 'text-sm text-text-secondary leading-relaxed mb-3'
    : 'text-base text-text-secondary leading-relaxed mb-4';
  const heading1Class = compact
    ? 'text-xl font-semibold text-text-primary mt-2 mb-2 tracking-tight'
    : 'text-2xl font-semibold text-text-primary mt-3 mb-3 tracking-tight';
  const heading2Class = compact
    ? 'text-base font-semibold text-text-primary mt-5 mb-3 pb-2 border-b'
    : 'text-lg font-semibold text-text-primary mt-6 mb-4 pb-2 border-b';
  const heading3Class = compact
    ? 'text-sm font-semibold text-text-primary mt-3 mb-2'
    : 'text-base font-semibold text-text-primary mt-4 mb-2';

  return (
    <div className={`max-w-none ${className}`.trim()}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => <h1 className={heading1Class}>{children}</h1>,
          h2: ({ children }) => <h2 className={heading2Class} style={{ borderColor: '#e8eaed' }}>{children}</h2>,
          h3: ({ children }) => <h3 className={heading3Class}>{children}</h3>,
          p: ({ children }) => <p className={paragraphClass}>{children}</p>,
          strong: ({ children }) => <strong className="text-text-primary font-semibold">{children}</strong>,
          em: ({ children }) => <em className="italic text-text-secondary">{children}</em>,
          ul: ({ children }) => (
            <ul className={`list-disc pl-5 ${compact ? 'mb-3' : 'mb-4'} space-y-1 text-text-secondary`}>{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className={`list-decimal pl-5 ${compact ? 'mb-3' : 'mb-4'} space-y-1 text-text-secondary`}>{children}</ol>
          ),
          li: ({ children }) => (
            <li className={`${compact ? 'text-sm' : 'text-base'} leading-relaxed mb-1`}>{children}</li>
          ),
          code: ({ children, className: codeClassName }) => {
            const isBlock = Boolean(codeClassName);
            if (isBlock) {
              return (
                <code className={`${codeClassName} font-mono text-xs text-text-secondary`}>
                  {children}
                </code>
              );
            }
            return (
              <code
                className="px-1.5 py-0.5 rounded text-xs font-mono"
                style={{
                  background: '#e8f0fe',
                  border: '1px solid #d2e3fc',
                  color: '#174ea6',
                }}
              >
                {children}
              </code>
            );
          },
          pre: ({ children }) => (
            <pre
              className={`${compact ? 'p-3' : 'p-4'} rounded-lg overflow-x-auto ${compact ? 'my-3' : 'my-4'}`}
              style={{
                background: '#f8fafd',
                border: '1px solid #e8eaed',
              }}
            >
              {children}
            </pre>
          ),
          a: ({ children, href }) => (
            <a href={href} target="_blank" rel="noreferrer" className="text-accent-blue underline break-all">
              {children}
            </a>
          ),
          blockquote: ({ children }) => (
            <blockquote
              className={`${compact ? 'my-3' : 'my-4'} pl-4 italic text-text-secondary`}
              style={{ borderLeft: '3px solid #1a73e8' }}
            >
              {children}
            </blockquote>
          ),
          hr: () => (
            <hr
              className={`${compact ? 'my-3' : 'my-4'}`}
              style={{ borderColor: '#e8eaed' }}
            />
          ),
          table: ({ children }) => (
            <div
              className={`overflow-x-auto ${compact ? 'my-3' : 'my-4'} rounded-xl`}
              style={{
                border: '1px solid #e8eaed',
                boxShadow: '0 1px 2px rgba(60,64,67,0.08)',
              }}
            >
              <table
                className="w-full text-left border-collapse"
              >
                {children}
              </table>
            </div>
          ),
          thead: ({ children }) => (
            <thead style={{ background: '#f8fafd' }}>{children}</thead>
          ),
          tbody: ({ children }) => <tbody>{children}</tbody>,
          tr: ({ children }) => (
            <tr
              className="border-b"
              style={{ borderColor: '#edf0f4' }}
            >
              {children}
            </tr>
          ),
          th: ({ children }) => (
            <th
              className="px-3 py-2 text-xs font-semibold uppercase text-text-secondary"
              style={{ borderBottom: '1px solid #e8eaed' }}
            >
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="px-3 py-2 align-top text-sm text-text-secondary">{children}</td>
          ),
        }}
      >
        {markdown}
      </ReactMarkdown>
    </div>
  );
}

export default MarkdownContent;
