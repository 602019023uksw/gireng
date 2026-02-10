import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  GitBranch, Network, AlertTriangle, Search, ChevronDown, ChevronRight,
  Maximize2, Minimize2, RotateCcw, ZoomIn, ZoomOut,
} from 'lucide-react';
import type { CallGraphAnalysis, CallGraphRaw, AttackChain, AdjacencyRow } from '@/lib/api';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */
interface CallGraphPanel {
  source: 'Ghidra' | 'Radare2';
  analysis: CallGraphAnalysis;
  rawGraph?: CallGraphRaw;
}

interface Props {
  panels: CallGraphPanel[];
}

type SubTab = 'chains' | 'adjacency' | 'cycles' | 'graph';

/* ------------------------------------------------------------------ */
/*  Layout – force-directed (simplified Fruchterman-Reingold)          */
/* ------------------------------------------------------------------ */
interface LayoutNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  kind: 'entry' | 'sink' | 'internal';
}
interface LayoutEdge {
  from: string;
  to: string;
}

const SINK_PATTERNS = new Set([
  'system', 'popen', 'execve', 'execv', 'execl', 'createprocess', 'winexec',
  'socket', 'connect', 'send', 'sendto', 'recv', 'recvfrom', 'wsastartup',
  'fopen', 'fwrite', 'fclose', 'open', 'write', 'read',
  'encrypt', 'decrypt', 'crypt', 'aes', 'rsa',
]);

function normalizeName(n: string) {
  let s = (n || '').toLowerCase().trim();
  for (const p of ['sym.imp.', 'imp.', 'sym.', 'fcn.', '__imp_']) {
    if (s.startsWith(p)) s = s.slice(p.length);
  }
  return s;
}

function isSink(name: string) {
  const n = normalizeName(name);
  for (const p of SINK_PATTERNS) {
    if (n.includes(p)) return true;
  }
  return false;
}

function computeLayout(
  raw: CallGraphRaw,
  entries: Set<string>,
  width: number,
  height: number,
): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  const nodeMap = new Map<string, LayoutNode>();
  const edges: LayoutEdge[] = [];

  for (const n of raw.nodes || []) {
    if (!n.name) continue;
    nodeMap.set(n.name, {
      id: n.name,
      x: width / 2 + (Math.random() - 0.5) * width * 0.8,
      y: height / 2 + (Math.random() - 0.5) * height * 0.8,
      vx: 0,
      vy: 0,
      kind: entries.has(n.name) ? 'entry' : isSink(n.name) ? 'sink' : 'internal',
    });
  }

  const addrToName = new Map<string, string>();
  for (const n of raw.nodes || []) {
    if (n.name && n.address != null) addrToName.set(String(n.address), n.name);
  }

  for (const e of raw.edges || []) {
    const src = e.from_name || addrToName.get(String(e.from)) || String(e.from);
    const dst = e.to_name || addrToName.get(String(e.to)) || String(e.to);
    if (src && dst && src !== dst && nodeMap.has(src) && nodeMap.has(dst)) {
      edges.push({ from: src, to: dst });
    }
  }

  // Cap for performance
  const nodeArr = Array.from(nodeMap.values());
  if (nodeArr.length > 200) {
    return { nodes: nodeArr.slice(0, 200), edges: edges.slice(0, 500) };
  }

  // Force-directed layout iterations
  const iterations = Math.min(120, Math.max(60, 300 - nodeArr.length * 2));
  const k = Math.sqrt((width * height) / Math.max(nodeArr.length, 1));
  const margin = 40;

  for (let iter = 0; iter < iterations; iter++) {
    const temp = 1 - iter / iterations;
    const maxMove = k * 2 * temp;

    // Repulsion
    for (let i = 0; i < nodeArr.length; i++) {
      nodeArr[i].vx = 0;
      nodeArr[i].vy = 0;
      for (let j = i + 1; j < nodeArr.length; j++) {
        let dx = nodeArr[i].x - nodeArr[j].x;
        let dy = nodeArr[i].y - nodeArr[j].y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = (k * k) / dist;
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        nodeArr[i].vx += dx;
        nodeArr[i].vy += dy;
        nodeArr[j].vx -= dx;
        nodeArr[j].vy -= dy;
      }
    }

    // Attraction along edges
    for (const e of edges) {
      const src = nodeMap.get(e.from)!;
      const dst = nodeMap.get(e.to)!;
      if (!src || !dst) continue;
      let dx = dst.x - src.x;
      let dy = dst.y - src.y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const force = (dist * dist) / k;
      dx = (dx / dist) * force * 0.3;
      dy = (dy / dist) * force * 0.3;
      src.vx += dx;
      src.vy += dy;
      dst.vx -= dx;
      dst.vy -= dy;
    }

    // Gravity toward center
    for (const n of nodeArr) {
      const dx = width / 2 - n.x;
      const dy = height / 2 - n.y;
      n.vx += dx * 0.01;
      n.vy += dy * 0.01;
    }

    // Apply velocities with clamping
    for (const n of nodeArr) {
      const len = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
      if (len > maxMove) {
        n.vx = (n.vx / len) * maxMove;
        n.vy = (n.vy / len) * maxMove;
      }
      n.x = Math.max(margin, Math.min(width - margin, n.x + n.vx));
      n.y = Math.max(margin, Math.min(height - margin, n.y + n.vy));
    }
  }

  return { nodes: nodeArr, edges };
}

/* ------------------------------------------------------------------ */
/*  SVG Graph Component                                                */
/* ------------------------------------------------------------------ */
function GraphVisualization({ panel }: { panel: CallGraphPanel }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, tx: 0, ty: 0 });
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    if (!containerRef.current) return;
    const obs = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        setDimensions({
          width: Math.max(entry.contentRect.width, 400),
          height: isFullscreen ? Math.max(window.innerHeight - 200, 500) : 500,
        });
      }
    });
    obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, [isFullscreen]);

  const entriesSet = useMemo(
    () => new Set(panel.analysis.entries || []),
    [panel.analysis.entries],
  );

  const layout = useMemo(() => {
    if (!panel.rawGraph?.nodes?.length) return null;
    return computeLayout(panel.rawGraph, entriesSet, dimensions.width, dimensions.height);
  }, [panel.rawGraph, entriesSet, dimensions.width, dimensions.height]);

  // Connected nodes for hover highlighting
  const connectedTo = useMemo(() => {
    if (!layout) return new Map<string, Set<string>>();
    const map = new Map<string, Set<string>>();
    for (const e of layout.edges) {
      if (!map.has(e.from)) map.set(e.from, new Set());
      if (!map.has(e.to)) map.set(e.to, new Set());
      map.get(e.from)!.add(e.to);
      map.get(e.to)!.add(e.from);
    }
    return map;
  }, [layout]);

  const isHighlighted = useCallback(
    (name: string) => {
      if (!hoveredNode) return true;
      if (name === hoveredNode) return true;
      return connectedTo.get(hoveredNode)?.has(name) ?? false;
    },
    [hoveredNode, connectedTo],
  );

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    setDragging(true);
    dragStart.current = { x: e.clientX, y: e.clientY, tx: transform.x, ty: transform.y };
  }, [transform]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging) return;
    setTransform((t) => ({
      ...t,
      x: dragStart.current.tx + (e.clientX - dragStart.current.x),
      y: dragStart.current.ty + (e.clientY - dragStart.current.y),
    }));
  }, [dragging]);

  const handleMouseUp = useCallback(() => setDragging(false), []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    setTransform((t) => ({
      ...t,
      scale: Math.max(0.2, Math.min(3, t.scale * (e.deltaY > 0 ? 0.92 : 1.08))),
    }));
  }, []);

  const resetView = useCallback(() => setTransform({ x: 0, y: 0, scale: 1 }), []);
  const zoomIn = useCallback(() => setTransform((t) => ({ ...t, scale: Math.min(3, t.scale * 1.2) })), []);
  const zoomOut = useCallback(() => setTransform((t) => ({ ...t, scale: Math.max(0.2, t.scale / 1.2) })), []);

  if (!layout || layout.nodes.length === 0) {
    return (
      <div className="text-center py-8 text-text-muted text-sm italic">
        No raw call graph data available for visualization.
      </div>
    );
  }

  const nodeColors = {
    entry: { fill: '#3b82f6', stroke: '#60a5fa' },
    sink: { fill: '#ef4444', stroke: '#f87171' },
    internal: { fill: '#6366f1', stroke: '#818cf8' },
  };

  const nodeById = new Map(layout.nodes.map((n) => [n.id, n]));

  return (
    <div className={isFullscreen ? 'fixed inset-0 z-50 bg-bg-primary p-4' : ''}>
      {/* Toolbar */}
      <div className="flex items-center gap-2 mb-2">
        <button onClick={zoomIn} className="p-1.5 rounded-md hover:bg-white/10 text-text-secondary" title="Zoom in">
          <ZoomIn size={14} />
        </button>
        <button onClick={zoomOut} className="p-1.5 rounded-md hover:bg-white/10 text-text-secondary" title="Zoom out">
          <ZoomOut size={14} />
        </button>
        <button onClick={resetView} className="p-1.5 rounded-md hover:bg-white/10 text-text-secondary" title="Reset view">
          <RotateCcw size={14} />
        </button>
        <button onClick={() => setIsFullscreen((f) => !f)} className="p-1.5 rounded-md hover:bg-white/10 text-text-secondary" title="Fullscreen">
          {isFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
        </button>
        <span className="text-[10px] text-text-muted ml-auto">
          {layout.nodes.length} nodes · {layout.edges.length} edges · scroll to zoom · drag to pan
        </span>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 mb-2 text-[10px] text-text-secondary">
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> Entry</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-500" /> Sink</span>
        <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-indigo-500" /> Internal</span>
      </div>

      <div
        ref={containerRef}
        className="rounded-xl overflow-hidden border border-white/10"
        style={{ background: 'rgba(5, 8, 18, 0.6)', cursor: dragging ? 'grabbing' : 'grab' }}
      >
        <svg
          width={dimensions.width}
          height={dimensions.height}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onWheel={handleWheel}
        >
          <defs>
            <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <path d="M0,0 L8,3 L0,6" fill="rgba(148, 163, 184, 0.5)" />
            </marker>
            <marker id="arrowhead-hl" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <path d="M0,0 L8,3 L0,6" fill="rgba(96, 165, 250, 0.8)" />
            </marker>
          </defs>
          <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>
            {/* Edges */}
            {layout.edges.map((e, i) => {
              const src = nodeById.get(e.from);
              const dst = nodeById.get(e.to);
              if (!src || !dst) return null;
              const edgeHighlighted = hoveredNode ? (e.from === hoveredNode || e.to === hoveredNode) : true;
              // Offset endpoint by node radius
              const dx = dst.x - src.x;
              const dy = dst.y - src.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const r = 6;
              return (
                <line
                  key={`edge-${i}`}
                  x1={src.x + (dx / dist) * r}
                  y1={src.y + (dy / dist) * r}
                  x2={dst.x - (dx / dist) * (r + 8)}
                  y2={dst.y - (dy / dist) * (r + 8)}
                  stroke={edgeHighlighted ? 'rgba(148, 163, 184, 0.35)' : 'rgba(148, 163, 184, 0.08)'}
                  strokeWidth={edgeHighlighted && hoveredNode ? 1.5 : 0.8}
                  markerEnd={edgeHighlighted ? 'url(#arrowhead-hl)' : 'url(#arrowhead)'}
                  style={{ transition: 'stroke 0.2s, opacity 0.2s' }}
                />
              );
            })}
            {/* Nodes */}
            {layout.nodes.map((n) => {
              const hl = isHighlighted(n.id);
              const color = nodeColors[n.kind];
              return (
                <g
                  key={n.id}
                  onMouseEnter={() => setHoveredNode(n.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  style={{ cursor: 'pointer' }}
                >
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={n.kind === 'entry' ? 8 : n.kind === 'sink' ? 7 : 5}
                    fill={hl ? color.fill : 'rgba(50,50,70,0.4)'}
                    stroke={hl ? color.stroke : 'rgba(100,100,130,0.3)'}
                    strokeWidth={hoveredNode === n.id ? 2.5 : 1.2}
                    style={{ transition: 'fill 0.2s, stroke 0.2s' }}
                  />
                  {(transform.scale > 0.5 || hoveredNode === n.id) && (
                    <text
                      x={n.x}
                      y={n.y + (n.kind === 'entry' ? 16 : 13)}
                      textAnchor="middle"
                      fill={hl ? '#e2e8f0' : 'rgba(148,163,184,0.3)'}
                      fontSize={hoveredNode === n.id ? 11 : 9}
                      fontFamily="monospace"
                      style={{ transition: 'fill 0.2s', pointerEvents: 'none' }}
                    >
                      {n.id.length > 22 ? n.id.slice(0, 20) + '…' : n.id}
                    </text>
                  )}
                  {hoveredNode === n.id && (
                    <title>{n.id} ({n.kind})</title>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Adjacency Table                                                    */
/* ------------------------------------------------------------------ */
function AdjacencyTable({ rows }: { rows: AdjacencyRow[] }) {
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    if (!search) return rows;
    const q = search.toLowerCase();
    return rows.filter(
      (r) => r.function.toLowerCase().includes(q) || r.calls.some((c) => c.toLowerCase().includes(q)),
    );
  }, [rows, search]);

  const toggle = (fn: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(fn) ? next.delete(fn) : next.add(fn);
      return next;
    });

  if (rows.length === 0) {
    return <p className="text-xs text-text-muted italic">No adjacency data available.</p>;
  }

  return (
    <div>
      <div className="relative mb-3">
        <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter functions…"
          className="w-full pl-8 pr-3 py-1.5 rounded-lg text-xs bg-white/5 border border-white/10 text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent-blue/40"
        />
      </div>
      <div className="max-h-80 overflow-y-auto pr-1 space-y-0.5">
        {filtered.slice(0, 150).map((row) => {
          const isOpen = expanded.has(row.function);
          return (
            <div key={row.function}>
              <button
                onClick={() => toggle(row.function)}
                className="w-full flex items-center gap-1.5 px-2 py-1 rounded-md hover:bg-white/5 text-left"
              >
                {row.calls.length > 0 ? (
                  isOpen ? (
                    <ChevronDown size={12} className="text-text-muted flex-shrink-0" />
                  ) : (
                    <ChevronRight size={12} className="text-text-muted flex-shrink-0" />
                  )
                ) : (
                  <span className="w-3 flex-shrink-0" />
                )}
                <span className="font-mono text-xs text-text-primary truncate">{row.function}</span>
                <span className="ml-auto text-[10px] text-text-muted flex-shrink-0">
                  {row.calls.length} call{row.calls.length !== 1 ? 's' : ''}
                </span>
              </button>
              <AnimatePresence>
                {isOpen && row.calls.length > 0 && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.15 }}
                    className="overflow-hidden"
                  >
                    <div className="ml-7 pl-2 border-l border-white/10 space-y-0.5 py-1">
                      {row.calls.map((callee) => (
                        <div key={callee} className="font-mono text-[11px] text-accent-blue/80 truncate">
                          → {callee}
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
        {filtered.length > 150 && (
          <p className="text-[10px] text-text-muted text-center py-1">
            Showing 150 of {filtered.length} functions
          </p>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Cycles List                                                        */
/* ------------------------------------------------------------------ */
function CyclesList({ cycles }: { cycles: string[][] }) {
  if (cycles.length === 0) {
    return (
      <p className="text-xs text-text-muted italic">
        No recursive / cyclic call paths detected.
      </p>
    );
  }

  return (
    <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
      {cycles.slice(0, 40).map((cycle, idx) => (
        <div
          key={idx}
          className="flex items-start gap-2 px-2.5 py-1.5 rounded-lg bg-yellow-500/5 border border-yellow-500/15"
        >
          <AlertTriangle size={12} className="text-yellow-500 flex-shrink-0 mt-0.5" />
          <span className="font-mono text-[11px] text-text-secondary break-all">
            {cycle.join(' → ')}
          </span>
        </div>
      ))}
      {cycles.length > 40 && (
        <p className="text-[10px] text-text-muted text-center">
          Showing 40 of {cycles.length} cycles
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Attack Chains (improved)                                           */
/* ------------------------------------------------------------------ */
function ChainsList({ chains }: { chains: AttackChain[] }) {
  const [showAll, setShowAll] = useState(false);
  const display = showAll ? chains : chains.slice(0, 20);

  const categoryColors: Record<string, string> = {
    Execution: 'text-red-400 bg-red-500/10 border-red-500/20',
    Network: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    'File I/O': 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    Crypto: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  };

  if (chains.length === 0) {
    return (
      <p className="text-xs text-text-muted italic">
        No sink-reaching attack chains were detected.
      </p>
    );
  }

  return (
    <div className="space-y-1.5 max-h-96 overflow-y-auto pr-1">
      {display.map((chain, idx) => {
        const colorCls = categoryColors[chain.category] || 'text-slate-400 bg-slate-500/10 border-slate-500/20';
        return (
          <div key={idx} className="px-2.5 py-1.5 rounded-lg bg-white/[0.02] border border-white/10">
            <div className="flex items-center gap-2 mb-0.5">
              <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${colorCls}`}>
                {chain.category}
              </span>
              {chain.sink && (
                <span className="font-mono text-[10px] text-text-muted">→ {chain.sink}</span>
              )}
            </div>
            <div className="font-mono text-[11px] text-text-secondary">
              {(chain.path || []).join(' → ')}
            </div>
            {chain.description && (
              <p className="text-[10px] text-text-muted mt-0.5">{chain.description}</p>
            )}
          </div>
        );
      })}
      {chains.length > 20 && !showAll && (
        <button
          onClick={() => setShowAll(true)}
          className="text-[11px] text-accent-blue hover:underline w-full text-center py-1"
        >
          Show all {chains.length} chains
        </button>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main Call Graph View                                               */
/* ------------------------------------------------------------------ */
export default function CallGraphView({ panels }: Props) {
  const [activeSource, setActiveSource] = useState(0);
  const [subTab, setSubTab] = useState<SubTab>('chains');

  if (panels.length === 0) {
    return (
      <p className="text-sm text-text-muted italic">
        Call graph data is not available for this analysis.
      </p>
    );
  }

  const panel = panels[activeSource] || panels[0];
  const stats = panel.analysis.stats || {};
  const entries = panel.analysis.entries || [];
  const chains = panel.analysis.chains || [];
  const cycles = panel.analysis.cycles || [];
  const adjacency = panel.analysis.adjacency || [];

  const subTabs: { key: SubTab; label: string; icon: React.ReactNode; count?: number }[] = [
    { key: 'chains', label: 'Attack Chains', icon: <GitBranch size={13} />, count: chains.length },
    { key: 'adjacency', label: 'Adjacency', icon: <Network size={13} />, count: adjacency.length },
    { key: 'cycles', label: 'Cycles', icon: <AlertTriangle size={13} />, count: cycles.length },
    { key: 'graph', label: 'Graph', icon: <Maximize2 size={13} /> },
  ];

  return (
    <div className="space-y-4">
      {/* Source selector (if multiple) */}
      {panels.length > 1 && (
        <div className="flex gap-2">
          {panels.map((p, i) => (
            <button
              key={p.source}
              onClick={() => setActiveSource(i)}
              className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors ${
                i === activeSource
                  ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                  : 'bg-white/5 text-text-secondary hover:bg-white/10 border border-transparent'
              }`}
            >
              {p.source}
            </button>
          ))}
        </div>
      )}

      {/* Stats bar */}
      <div
        className="rounded-xl px-4 py-3 flex flex-wrap items-center gap-x-6 gap-y-1"
        style={{
          background: 'rgba(10, 16, 28, 0.45)',
          border: '1px solid rgba(100, 120, 180, 0.18)',
        }}
      >
        <h4 className="text-sm font-semibold text-text-primary">{panel.source}</h4>
        <StatBadge label="Nodes" value={stats.nodes ?? 0} />
        <StatBadge label="Edges" value={stats.edges ?? 0} />
        <StatBadge label="Chains" value={stats.chains ?? chains.length} />
        <StatBadge label="Cycles" value={stats.cycles ?? cycles.length} />
        {entries.length > 0 && (
          <span className="text-[10px] text-text-muted ml-auto max-w-[40%] truncate" title={entries.join(', ')}>
            Entry: {entries.slice(0, 5).join(', ')}{entries.length > 5 ? ` +${entries.length - 5}` : ''}
          </span>
        )}
      </div>

      {/* Sub-tabs */}
      <div className="flex gap-1 border-b border-white/10 pb-px">
        {subTabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setSubTab(t.key)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-t-lg transition-colors ${
              subTab === t.key
                ? 'bg-white/10 text-text-primary border-b-2 border-accent-blue'
                : 'text-text-muted hover:text-text-secondary hover:bg-white/5'
            }`}
          >
            {t.icon}
            {t.label}
            {t.count != null && (
              <span className="text-[10px] ml-0.5 text-text-muted">({t.count})</span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <motion.div
        key={`${panel.source}-${subTab}`}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
      >
        {subTab === 'chains' && <ChainsList chains={chains} />}
        {subTab === 'adjacency' && <AdjacencyTable rows={adjacency} />}
        {subTab === 'cycles' && <CyclesList cycles={cycles} />}
        {subTab === 'graph' && <GraphVisualization panel={panel} />}
      </motion.div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */
function StatBadge({ label, value }: { label: string; value: number }) {
  return (
    <span className="text-xs text-text-secondary">
      <span className="text-text-muted">{label}:</span>{' '}
      <span className="font-medium text-text-primary">{value}</span>
    </span>
  );
}
