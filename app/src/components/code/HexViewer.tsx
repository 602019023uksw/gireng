interface HexViewerProps {
  lines: string[];
}

export function HexViewer({ lines }: HexViewerProps) {
  return (
    <div className="p-4">
      <pre className="text-sm font-mono text-text-secondary leading-6">
        {lines.map((line, i) => (
          <div key={i} className="whitespace-pre hover:bg-white/5">
            {line}
          </div>
        ))}
      </pre>
    </div>
  );
}
