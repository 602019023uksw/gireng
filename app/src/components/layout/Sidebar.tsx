import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ChevronLeft, 
  Edit3, 
  Search, 
  Clock, 
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Trash2,
  Loader2,
} from 'lucide-react';
import { getHistory, restoreSession, deleteHistoryItem, type HistoryItem } from '@/lib/api';

interface SidebarProps {
  onNewChat?: () => void;
  onRestoreSession?: (sessionId: string, programHash: string) => void;
}

export function Sidebar({ 
  onNewChat,
  onRestoreSession,
}: SidebarProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [historyItems, setHistoryItems] = useState<HistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [restoringId, setRestoringId] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const resp = await getHistory(50, 0, '', searchQuery);
      setHistoryItems(resp.items);
    } catch {
      // silently fail
    } finally {
      setHistoryLoading(false);
    }
  }, [searchQuery]);

  useEffect(() => {
    loadHistory();
    // Refresh every 30s
    const interval = setInterval(loadHistory, 30000);
    return () => clearInterval(interval);
  }, [loadHistory]);

  const handleRestore = async (item: HistoryItem) => {
    setRestoringId(item.id);
    try {
      const resp = await restoreSession(item.id);
      if (resp?.ok && onRestoreSession) {
        onRestoreSession(resp.session_id, resp.program_hash);
      }
    } catch {
      // silently fail
    } finally {
      setRestoringId(null);
    }
  };

  const handleDelete = async (item: HistoryItem) => {
    await deleteHistoryItem(item.id);
    setHistoryItems(prev => prev.filter(h => h.id !== item.id));
  };

  const verdictIcon = (verdict: string | null) => {
    switch (verdict?.toLowerCase()) {
      case 'malware': return <ShieldAlert className="w-4 h-4 text-accent-red" />;
      case 'suspicious': return <ShieldQuestion className="w-4 h-4 text-accent-orange" />;
      case 'clean': return <ShieldCheck className="w-4 h-4 text-accent-green" />;
      default: return <Shield className="w-4 h-4 text-text-muted" />;
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return '';
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays}d ago`;
    return d.toLocaleDateString();
  };

  const binaryName = (path: string) => {
    const parts = path.replace(/\\/g, '/').split('/');
    return parts[parts.length - 1] || path;
  };

  return (
    <>
      {/* Main Sidebar */}
      <motion.aside
        initial={{ x: -20, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
        className="h-screen flex flex-shrink-0"
        style={{
          width: isCollapsed ? '56px' : '280px',
          background: 'rgba(255, 255, 255, 0.96)',
          borderRight: '1px solid #e8eaed',
          boxShadow: '1px 0 2px rgba(60, 64, 67, 0.06)',
          transition: 'width 0.3s ease',
        }}
      >
        {/* Collapsed: show icon to expand */}
        {isCollapsed && (
          <div className="flex flex-col items-center py-4 w-full">
            <button
              onClick={() => setIsCollapsed(false)}
              className="w-10 h-10 rounded-full flex items-center justify-center text-text-secondary hover:text-accent-blue hover:bg-bg-hover transition-all duration-150"
              title="Show History"
            >
              <Clock className="w-5 h-5" />
            </button>
          </div>
        )}

        {/* Content Panel */}
        <AnimatePresence>
          {!isCollapsed && (
            <motion.div
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: 'auto' }}
              exit={{ opacity: 0, width: 0 }}
              transition={{ duration: 0.2 }}
              className="flex-1 flex flex-col min-w-0 overflow-hidden"
            >
              {/* Header */}
              <div className="flex items-center justify-between px-5 py-4 border-b"
                style={{ borderColor: '#e8eaed' }}
              >
                <h2 className="text-base font-semibold text-text-primary tracking-tight">History</h2>
                <button 
                  onClick={() => setIsCollapsed(true)}
                  className="w-8 h-8 rounded-full flex items-center justify-center text-text-secondary hover:text-accent-blue transition-all duration-150 hover:bg-bg-hover"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
              </div>

              {/* New Chat Button */}
              <div className="px-4 py-3">
                <button
                  onClick={onNewChat}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-full text-white text-sm font-medium transition-all duration-150 hover:shadow-glass"
                  style={{
                    background: '#1a73e8',
                    border: '1px solid #1a73e8',
                  }}
                >
                  <Edit3 className="w-4 h-4" />
                  <span>New Chat</span>
                </button>
              </div>

              {/* Search */}
              <div className="px-4 pb-3">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                  <input
                    type="text"
                    placeholder="Search analyses..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-9 pr-3 py-2.5 rounded-full text-sm text-text-primary placeholder:text-text-muted focus:outline-none transition-all duration-150 focus:ring-4 focus:ring-blue-100"
                    style={{
                      background: '#f8fafd',
                      border: '1px solid #dadce0',
                    }}
                  />
                </div>
              </div>

              {/* Analysis History List */}
              <div className="flex-1 overflow-y-auto scrollbar-dark">
                {historyLoading && historyItems.length === 0 ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="w-5 h-5 text-text-muted animate-spin" />
                  </div>
                ) : historyItems.length === 0 ? (
                  <div className="px-4 py-8 text-center">
                    <Clock className="w-8 h-8 text-text-muted mx-auto mb-2 opacity-50" />
                    <p className="text-sm text-text-muted">No past analyses yet</p>
                    <p className="text-xs text-text-muted mt-1 opacity-60">Upload a binary to get started</p>
                  </div>
                ) : (
                  <div className="px-3 py-2 space-y-1">
                    {historyItems.map((item) => (
                      <div
                        key={item.id}
                        className="group relative px-3 py-3 rounded-2xl text-sm transition-all duration-150 cursor-pointer hover:bg-bg-hover"
                        style={{
                          border: '1px solid transparent',
                        }}
                        onClick={() => handleRestore(item)}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          {verdictIcon(item.verdict)}
                          <span className="text-text-primary font-medium truncate flex-1 text-xs">
                            {binaryName(item.binary_path)}
                          </span>
                          {restoringId === item.id && (
                            <Loader2 className="w-3 h-3 text-accent-blue animate-spin flex-shrink-0" />
                          )}
                        </div>
                        <div className="flex items-center gap-2 text-[10px] text-text-muted">
                          <span className="font-mono truncate" style={{ maxWidth: '90px' }}>
                            {item.program_hash?.slice(0, 12)}...
                          </span>
                          <span className="opacity-40">|</span>
                          <span className={
                            item.status === 'completed' ? 'text-accent-green' :
                            item.status === 'error' ? 'text-accent-red' :
                            item.status === 'running' ? 'text-accent-orange' :
                            'text-text-muted'
                          }>
                            {item.status}
                          </span>
                          <span className="opacity-40">|</span>
                          <span>{formatDate(item.created_at)}</span>
                        </div>
                        {item.verdict && (
                          <div className="mt-1">
                            <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                              item.verdict.toLowerCase() === 'malware' ? 'bg-red-50 text-accent-red border border-red-100' :
                              item.verdict.toLowerCase() === 'suspicious' ? 'bg-orange-50 text-accent-orange border border-orange-100' :
                              item.verdict.toLowerCase() === 'clean' ? 'bg-green-50 text-accent-green border border-green-100' :
                              'bg-slate-100 text-text-secondary border border-slate-200'
                            }`}>
                              {item.verdict}
                              {item.threat_score != null ? ` (${item.threat_score}/100)` : ''}
                            </span>
                          </div>
                        )}

                        {/* Hover actions */}
                        <div className="absolute right-2 top-2 hidden group-hover:flex gap-1">
                          <button
                            onClick={(e) => { e.stopPropagation(); handleDelete(item); }}
                            className="w-6 h-6 rounded-full flex items-center justify-center text-text-muted hover:text-accent-red hover:bg-red-50 transition-all"
                            title="Delete"
                          >
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.aside>
    </>
  );
}

export default Sidebar;
