import { motion } from 'framer-motion';
import {
  Activity,
  Cpu,
  Network,
  Shield,
  Terminal,
  HardDrive,
  AlertTriangle,
  Code,
} from 'lucide-react';
import type { AnalyzerRawResults } from '@/lib/api';

interface QilingResultsViewProps {
  results: AnalyzerRawResults;
}

/* ---------- helpers ---------- */

function asRecord(v: unknown): Record<string, unknown> {
  return typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : {};
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function asString(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}

function asNumber(v: unknown, fallback = 0): number {
  return typeof v === 'number' ? v : fallback;
}

/* ---------- sub-components ---------- */

function SectionCard({
  title,
  icon: Icon,
  children,
  badge,
}: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  badge?: string | number;
}) {
  return (
    <div
      className="rounded-2xl bg-white p-4 mb-4"
      style={{
        border: '1px solid #e8eaed',
        boxShadow: '0 1px 2px rgba(60, 64, 67, 0.08)',
      }}
    >
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-4 h-4 text-accent-blue" />
        <h4 className="text-sm font-semibold text-text-primary">{title}</h4>
        {badge !== undefined && (
          <span
            className="ml-auto text-xs px-2 py-0.5 rounded-full"
            style={{
              background: '#e8f0fe',
              color: '#1a73e8',
            }}
          >
            {badge}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

function KVRow({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-border-subtle last:border-0">
      <span className="text-xs text-text-secondary">{label}</span>
      <span className={`text-xs text-text-primary ${mono ? 'font-mono' : ''}`}>{String(value)}</span>
    </div>
  );
}

/* ---------- sections ---------- */

function fmtInt(n: number): string {
  // Explicitly use en-US to avoid locale-dependent separators (e.g. "7.568" on de-DE)
  return n.toLocaleString('en-US');
}

function ExecutionTraceSection({ data }: { data: Record<string, unknown> }) {
  if (!data || Object.keys(data).length === 0) return null;
  const instructions = asNumber(data.instructions_executed);
  // Backend sends `duration_ms`; fall back to `duration_seconds` for compat
  const durationMs = data.duration_ms ?? data.duration_seconds;
  const duration =
    durationMs != null
      ? `${(asNumber(durationMs) / (data.duration_ms != null ? 1000 : 1)).toFixed(2)}s`
      : 'N/A';
  const exitReason = asString(data.exit_reason, 'unknown');
  // Backend sends `arch` and `os`; fall back to legacy names for compat
  const arch = asString(data.arch || data.architecture, 'N/A');
  const os = asString(data.os || data.os_type, 'N/A');
  // entry_point may already be a hex string like "0x409b11" or a number
  const epRaw = data.entry_point;
  const entryPoint =
    typeof epRaw === 'string' && epRaw.length > 0
      ? (epRaw.startsWith('0x') ? epRaw : `0x${epRaw}`)
      : typeof epRaw === 'number'
        ? `0x${epRaw.toString(16)}`
        : 'N/A';
  const rootfs = asString(data.rootfs, 'N/A');

  return (
    <SectionCard title="Execution Trace" icon={Cpu} badge={`${fmtInt(instructions)} instr`}>
      <KVRow label="Instructions Executed" value={fmtInt(instructions)} />
      <KVRow label="Duration" value={duration} />
      <KVRow label="Exit Reason" value={exitReason} />
      <KVRow label="Architecture" value={arch} />
      <KVRow label="OS Type" value={os} />
      <KVRow label="Entry Point" value={entryPoint} mono />
      <KVRow label="Root FS" value={rootfs} />
    </SectionCard>
  );
}

function SyscallsSection({ data }: { data: Record<string, unknown> }) {
  const syscalls = asArray(data.syscalls || data.items);
  const summary = asRecord(data.summary);
  const total = asNumber(summary.total_syscalls || syscalls.length);
  if (total === 0 && syscalls.length === 0) return null;

  // Group by category if available
  const categories = asRecord(summary.categories || summary.by_category);

  return (
    <SectionCard title="System Calls" icon={Terminal} badge={total}>
      {Object.keys(categories).length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-text-muted mb-2">By Category</p>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(categories).map(([cat, count]) => (
              <span
                key={cat}
                className="text-xs px-2 py-0.5 rounded-full"
                style={{
                  background: '#e8f0fe',
                  border: '1px solid #d2e3fc',
                  color: '#174ea6',
                }}
              >
                {cat}: {String(count)}
              </span>
            ))}
          </div>
        </div>
      )}
      {syscalls.length > 0 && (
        <div className="max-h-48 overflow-y-auto scrollbar-dark">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-muted border-b border-border-subtle">
                <th className="text-left py-1 pr-2">Name</th>
                <th className="text-left py-1 pr-2">Category</th>
                <th className="text-right py-1">Address</th>
              </tr>
            </thead>
            <tbody>
              {syscalls.slice(0, 50).map((sc, i) => {
                const s = asRecord(sc);
                return (
                  <tr key={i} className="border-b border-border-subtle hover:bg-bg-hover">
                    <td className="py-1 pr-2 text-text-primary font-mono">{asString(s.name || s.syscall, '?')}</td>
                    <td className="py-1 pr-2 text-text-secondary">{asString(s.category, '-')}</td>
                    <td className="py-1 text-right text-text-muted font-mono">
                      {s.address ? `0x${Number(s.address).toString(16)}` : '-'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {syscalls.length > 50 && (
            <p className="text-xs text-text-muted mt-1">... and {syscalls.length - 50} more</p>
          )}
        </div>
      )}
    </SectionCard>
  );
}

function MemorySection({ data }: { data: Record<string, unknown> }) {
  const events = asArray(data.events || data.items);
  const indicators = asRecord(data.indicators);
  if (events.length === 0 && Object.keys(indicators).length === 0) return null;

  return (
    <SectionCard title="Memory Events" icon={HardDrive} badge={events.length}>
      {Object.keys(indicators).length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-text-muted mb-2">Indicators</p>
          {Object.entries(indicators).map(([key, val]) => (
            <KVRow key={key} label={key.replace(/_/g, ' ')} value={String(val)} />
          ))}
        </div>
      )}
      {events.length > 0 && (
        <div className="max-h-40 overflow-y-auto scrollbar-dark">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-muted border-b border-border-subtle">
                <th className="text-left py-1 pr-2">Type</th>
                <th className="text-left py-1 pr-2">Address</th>
                <th className="text-right py-1">Size</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 30).map((ev, i) => {
                const e = asRecord(ev);
                return (
                  <tr key={i} className="border-b border-border-subtle hover:bg-bg-hover">
                    <td className="py-1 pr-2 text-text-primary">{asString(e.type || e.event_type, '?')}</td>
                    <td className="py-1 pr-2 text-text-muted font-mono">
                      {(() => {
                        const addr = e.target_address || e.address;
                        if (!addr) return '-';
                        // Already a hex string like "0x1234"
                        if (typeof addr === 'string') return addr.startsWith('0x') ? addr : `0x${addr}`;
                        if (typeof addr === 'number') return `0x${addr.toString(16)}`;
                        return '-';
                      })()}
                    </td>
                    <td className="py-1 text-right text-text-secondary">
                      {e.size != null ? String(e.size) : '-'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {events.length > 30 && (
            <p className="text-xs text-text-muted mt-1">... and {events.length - 30} more</p>
          )}
        </div>
      )}
    </SectionCard>
  );
}

function NetworkSection({ data }: { data: Record<string, unknown> }) {
  const connections = asArray(data.connections);
  const dnsQueries = asArray(data.dns_queries);
  const dataSent = asArray(data.data_sent);
  const indicators = asRecord(data.indicators);
  const total = connections.length + dnsQueries.length + dataSent.length;
  // Check if indicators have any actual content (not just empty arrays)
  const hasRealIndicators = Object.values(indicators).some(
    (v) => (Array.isArray(v) ? v.length > 0 : v != null && v !== '' && v !== false && v !== 0),
  );
  if (total === 0 && !hasRealIndicators) return null;

  return (
    <SectionCard title="Network Activity" icon={Network} badge={total || undefined}>
      {Object.keys(indicators).length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-text-muted mb-2">Indicators</p>
          {Object.entries(indicators).map(([key, val]) => {
            // Format arrays nicely (e.g. c2_candidates, dns_domains)
            const display = Array.isArray(val)
              ? (val.length > 0 ? val.join(', ') : 'none')
              : String(val);
            return <KVRow key={key} label={key.replace(/_/g, ' ')} value={display} />;
          })}
        </div>
      )}
      {connections.length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-text-muted mb-2">Connections ({connections.length})</p>
          <div className="max-h-32 overflow-y-auto scrollbar-dark space-y-1">
            {connections.map((conn, i) => {
              const c = asRecord(conn);
              return (
                <div
                  key={i}
                  className="text-xs font-mono text-text-primary px-2 py-1 rounded"
                  style={{ background: '#fce8e6' }}
                >
                  {asString(c.protocol || c.type, 'TCP')} {asString(c.destination || c.address || c.ip, '?')}:{String(c.port || '?')}
                </div>
              );
            })}
          </div>
        </div>
      )}
      {dnsQueries.length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-text-muted mb-2">DNS Queries ({dnsQueries.length})</p>
          <div className="max-h-32 overflow-y-auto scrollbar-dark space-y-1">
            {dnsQueries.map((q, i) => {
              const d = asRecord(q);
              return (
                <div key={i} className="text-xs font-mono text-text-primary px-2 py-1 rounded" style={{ background: '#fff4e5' }}>
                  {asString(d.domain || d.query, '?')} ({asString(d.type, 'A')})
                </div>
              );
            })}
          </div>
        </div>
      )}
    </SectionCard>
  );
}

function EvasionSection({ data }: { data: Record<string, unknown> }) {
  const techniques = asArray(data.techniques);
  const summary = asRecord(data.summary);
  const riskLevel = asString(summary.risk_level, 'low');
  const mitre = asArray(summary.mitre_tactics);
  // Only show if there are actual techniques or a non-trivial risk level
  if (techniques.length === 0 && riskLevel === 'low' && mitre.length === 0) return null;

  const riskColor =
    riskLevel === 'high' ? 'text-accent-red' :
    riskLevel === 'medium' ? 'text-accent-orange' :
    'text-accent-green';

  return (
    <SectionCard title="Evasion Techniques" icon={Shield} badge={techniques.length || undefined}>
      {riskLevel !== 'low' && (
        <div className="flex items-center gap-2 mb-2">
          <AlertTriangle className={`w-3.5 h-3.5 ${riskColor}`} />
          <span className={`text-xs font-medium uppercase ${riskColor}`}>{riskLevel} risk</span>
        </div>
      )}
      {mitre.length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-text-muted mb-1">MITRE ATT&CK Tactics</p>
          <div className="flex flex-wrap gap-1">
            {mitre.map((t, i) => (
              <span
                key={i}
                className="text-xs px-2 py-0.5 rounded-full"
                style={{
                  background: '#fce8e6',
                  border: '1px solid #fad2cf',
                  color: '#d93025',
                }}
              >
                {String(t)}
              </span>
            ))}
          </div>
        </div>
      )}
      {techniques.length > 0 && (
        <div className="space-y-2">
          {techniques.map((tech, i) => {
            const t = asRecord(tech);
            return (
              <div
                key={i}
                className="text-xs p-2 rounded"
                style={{ background: '#fce8e6', border: '1px solid #fad2cf' }}
              >
                <span className="text-text-primary font-medium">{asString(t.name || t.technique, 'Unknown')}</span>
                {t.description ? (
                  <p className="text-text-muted mt-0.5">{asString(t.description)}</p>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
    </SectionCard>
  );
}

function InstructionTraceSection({ data }: { data: Record<string, unknown> }) {
  const instructions = asArray(data.instructions);
  const summary = asRecord(data.summary);
  const totalExecuted = asNumber(summary.total_executed);
  const traced = asNumber(summary.traced);
  const uniqueMnemonics = asNumber(summary.unique_mnemonics);
  const topMnemonics = asArray(summary.top_mnemonics);
  const addressRange = asRecord(summary.address_range);
  const disasmErrors = asNumber(summary.disasm_errors);
  const sampleRate = asNumber(summary.sample_rate, 1);

  if (totalExecuted === 0 && instructions.length === 0) return null;

  return (
    <SectionCard
      title="Instruction Trace"
      icon={Code}
      badge={`${fmtInt(totalExecuted)} executed`}
    >
      {/* Summary stats */}
      <div className="mb-3">
        <KVRow label="Total Executed" value={fmtInt(totalExecuted)} />
        <KVRow label="Traced (stored)" value={fmtInt(traced)} />
        <KVRow label="Unique Mnemonics" value={fmtInt(uniqueMnemonics)} />
        {sampleRate > 1 && <KVRow label="Sample Rate" value={`1 / ${sampleRate}`} />}
        {disasmErrors > 0 && <KVRow label="Disasm Errors" value={fmtInt(disasmErrors)} />}
        {addressRange.low != null && (
          <KVRow
            label="Address Range"
            value={`${asString(addressRange.low)} — ${asString(addressRange.high)}`}
            mono
          />
        )}
      </div>

      {/* Top mnemonics */}
      {topMnemonics.length > 0 && (
        <div className="mb-3">
          <p className="text-xs text-text-muted mb-2">Top Mnemonics</p>
          <div className="flex flex-wrap gap-1.5">
            {topMnemonics.slice(0, 20).map((m, i) => {
              const item = asRecord(m);
              return (
                <span
                  key={i}
                  className="text-xs px-2 py-0.5 rounded-full font-mono"
                  style={{
                    background: '#e8f0fe',
                    border: '1px solid #d2e3fc',
                    color: '#174ea6',
                  }}
                >
                  {asString(item.mnemonic, '?')}: {fmtInt(asNumber(item.count))}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Instruction table */}
      {instructions.length > 0 && (
        <div className="max-h-64 overflow-y-auto scrollbar-dark">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-muted border-b border-border-subtle">
                <th className="text-left py-1 pr-2">Address</th>
                <th className="text-left py-1 pr-2">Mnemonic</th>
                <th className="text-left py-1 pr-2">Operands</th>
                <th className="text-right py-1">Size</th>
              </tr>
            </thead>
            <tbody>
              {instructions.slice(0, 200).map((insn, i) => {
                const ins = asRecord(insn);
                return (
                  <tr key={i} className="border-b border-border-subtle hover:bg-bg-hover">
                    <td className="py-1 pr-2 text-accent-blue font-mono">
                      {asString(ins.address, '?')}
                    </td>
                    <td className="py-1 pr-2 text-text-primary font-mono font-semibold">
                      {asString(ins.mnemonic, '?')}
                    </td>
                    <td className="py-1 pr-2 text-text-secondary font-mono">
                      {asString(ins.operands, '')}
                    </td>
                    <td className="py-1 text-right text-text-muted">
                      {ins.size != null ? String(ins.size) : '-'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {instructions.length > 200 && (
            <p className="text-xs text-text-muted mt-1">
              ... and {fmtInt(instructions.length - 200)} more (of {fmtInt(traced)} traced)
            </p>
          )}
        </div>
      )}
    </SectionCard>
  );
}

function ApiCallsSection({ data }: { data: Record<string, unknown> }) {
  const calls = asArray(data.calls || data.items || data.api_calls);
  if (calls.length === 0) return null;

  return (
    <SectionCard title="API Calls" icon={Activity} badge={calls.length}>
      <div className="max-h-48 overflow-y-auto scrollbar-dark">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-text-muted border-b border-border-subtle">
              <th className="text-left py-1 pr-2">Function</th>
              <th className="text-left py-1 pr-2">Module</th>
              <th className="text-right py-1">Return</th>
            </tr>
          </thead>
          <tbody>
            {calls.slice(0, 50).map((c, i) => {
              const call = asRecord(c);
              return (
                <tr key={i} className="border-b border-border-subtle hover:bg-bg-hover">
                  <td className="py-1 pr-2 text-text-primary font-mono">{asString(call.name || call.function, '?')}</td>
                  <td className="py-1 pr-2 text-text-secondary">{asString(call.module, '-')}</td>
                  <td className="py-1 text-right text-text-muted font-mono">{call.return_value != null ? String(call.return_value) : '-'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {calls.length > 50 && (
          <p className="text-xs text-text-muted mt-1">... and {calls.length - 50} more</p>
        )}
      </div>
    </SectionCard>
  );
}

/* ---------- main component ---------- */

export function QilingResultsView({ results }: QilingResultsViewProps) {
  const executionTrace = asRecord(results.execution_trace);
  const syscalls = asRecord(results.syscalls);
  const apiCalls = asRecord(results.api_calls);
  const memoryEvents = asRecord(results.memory_events);
  const networkActivity = asRecord(results.network_activity);
  const evasionTechniques = asRecord(results.evasion_techniques);
  const instructionTrace = asRecord(results.instruction_trace);
  const errors = asArray(results.errors);

  const hasData =
    Object.keys(executionTrace).length > 0 ||
    Object.keys(syscalls).length > 0 ||
    Object.keys(memoryEvents).length > 0 ||
    Object.keys(networkActivity).length > 0 ||
    Object.keys(instructionTrace).length > 0;

  if (!hasData) {
    return (
      <div className="text-sm text-text-muted italic p-4">
        No Qiling dynamic analysis data available.
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <ExecutionTraceSection data={executionTrace} />
      <InstructionTraceSection data={instructionTrace} />
      <SyscallsSection data={syscalls} />
      <ApiCallsSection data={apiCalls} />
      <MemorySection data={memoryEvents} />
      <NetworkSection data={networkActivity} />
      <EvasionSection data={evasionTechniques} />

      {errors.length > 0 && (
        <SectionCard title="Errors" icon={AlertTriangle}>
          <div className="space-y-1">
            {errors.map((err, i) => (
              <p key={i} className="text-xs text-accent-red font-mono">{String(err)}</p>
            ))}
          </div>
        </SectionCard>
      )}
    </motion.div>
  );
}

export default QilingResultsView;
