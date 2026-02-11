import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface MarkdownContentProps {
  content: string;
  compact?: boolean;
  className?: string;
}

function normalizeMarkdown(content: string): string {
  return content
    .replace(/\r\n/g, '\n')
    .replace(/\u2022/g, '- ')
    .replace(/â€¢/g, '- ')
    .replace(/\u2192/g, '->')
    .replace(/â†’/g, '->')
    .replace(/â€”/g, '--')
    .replace(/\u00A0/g, ' ')
    .trim();
}

export function MarkdownContent({ content, compact = false, className = '' }: MarkdownContentProps) {
  const markdown = normalizeMarkdown(content);
  const paragraphClass = compact
    ? 'text-sm text-text-secondary leading-relaxed mb-3'
    : 'text-base text-text-secondary leading-relaxed mb-4';
  const heading1Class = compact
    ? 'text-lg font-semibold text-text-primary mt-5 mb-3'
    : 'text-xl font-semibold text-text-primary mt-6 mb-4';
  const heading2Class = compact
    ? 'text-base font-semibold text-text-primary mt-4 mb-2'
    : 'text-lg font-semibold text-text-primary mt-5 mb-3';
  const heading3Class = compact
    ? 'text-sm font-semibold text-text-primary mt-3 mb-2'
    : 'text-base font-semibold text-text-primary mt-4 mb-2';

  return (
    <div className={`max-w-none ${className}`.trim()}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => <h1 className={heading1Class}>{children}</h1>,
          h2: ({ children }) => <h2 className={heading2Class}>{children}</h2>,
          h3: ({ children }) => <h3 className={heading3Class}>{children}</h3>,
          p: ({ children }) => <p className={paragraphClass}>{children}</p>,
          strong: ({ children }) => <strong className="text-text-primary font-semibold">{children}</strong>,
          em: ({ children }) => <em className="italic text-text-secondary">{children}</em>,
          ul: ({ children }) => (
            <ul className={`list-disc pl-5 ${compact ? 'mb-3' : 'mb-4'} text-text-secondary`}>{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className={`list-decimal pl-5 ${compact ? 'mb-3' : 'mb-4'} text-text-secondary`}>{children}</ol>
          ),
          li: ({ children }) => (
            <li className={`${compact ? 'text-sm' : 'text-base'} leading-relaxed mb-1`}>{children}</li>
          ),
          code: ({ children, className: codeClassName }) => {
            const isBlock = Boolean(codeClassName);
            if (isBlock) {
              return (
                <code className={`${codeClassName} font-mono text-xs text-[#F0F6FC]`}>
                  {children}
                </code>
              );
            }
            return (
              <code
                className="px-1.5 py-0.5 rounded text-xs font-mono"
                style={{
                  background: 'rgba(88, 166, 255, 0.1)',
                  border: '1px solid rgba(88, 166, 255, 0.2)',
                  color: '#F0F6FC',
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
                background: 'rgba(10, 14, 28, 0.6)',
                border: '1px solid rgba(100, 120, 180, 0.15)',
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
              style={{ borderLeft: '3px solid rgba(88, 166, 255, 0.45)' }}
            >
              {children}
            </blockquote>
          ),
          hr: () => (
            <hr
              className={`${compact ? 'my-3' : 'my-4'}`}
              style={{ borderColor: 'rgba(100, 120, 180, 0.2)' }}
            />
          ),
          table: ({ children }) => (
            <div className={`overflow-x-auto ${compact ? 'my-3' : 'my-4'}`}>
              <table
                className="w-full text-left border-collapse"
                style={{ border: '1px solid rgba(100, 120, 180, 0.2)' }}
              >
                {children}
              </table>
            </div>
          ),
          thead: ({ children }) => (
            <thead style={{ background: 'rgba(20, 28, 50, 0.6)' }}>{children}</thead>
          ),
          tbody: ({ children }) => <tbody>{children}</tbody>,
          tr: ({ children }) => (
            <tr
              className="border-b"
              style={{ borderColor: 'rgba(100, 120, 180, 0.12)' }}
            >
              {children}
            </tr>
          ),
          th: ({ children }) => (
            <th
              className="px-3 py-2 text-xs font-semibold uppercase text-text-secondary"
              style={{ borderBottom: '2px solid rgba(100, 120, 180, 0.25)' }}
            >
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="px-3 py-2 text-sm text-text-secondary">{children}</td>
          ),
        }}
      >
        {markdown}
      </ReactMarkdown>
    </div>
  );
}

export default MarkdownContent;
