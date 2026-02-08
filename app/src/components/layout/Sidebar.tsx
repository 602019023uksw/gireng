import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ChevronLeft, 
  ChevronRight,
  Edit3, 
  Search, 
  Clock, 
  Plug, 
  FileText, 
  Calendar,
  MessageSquare
} from 'lucide-react';
import type { Chat, NavItem } from '@/types';

interface SidebarProps {
  chats?: Chat[];
  activeChatId?: string;
  onChatSelect?: (chatId: string) => void;
  onNewChat?: () => void;
}

const navItems: NavItem[] = [
  { id: 'history', icon: 'Clock', label: 'History' },
  { id: 'plugins', icon: 'Plug', label: 'Plugins' },
  { id: 'files', icon: 'FileText', label: 'Files', hasNotification: true },
  { id: 'calendar', icon: 'Calendar', label: 'Calendar' },
];

const iconMap: Record<string, React.ElementType> = {
  Clock,
  Plug,
  FileText,
  Calendar,
};

export function Sidebar({ 
  chats = [], 
  activeChatId, 
  onChatSelect, 
  onNewChat 
}: SidebarProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [isCollapsed, setIsCollapsed] = useState(false);

  const filteredChats = chats.filter(chat => 
    chat.title.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <>
      {/* Main Sidebar */}
      <motion.aside
        initial={{ x: -20, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] as const }}
        className="h-screen backdrop-blur-xl flex flex-shrink-0"
        style={{
          width: isCollapsed ? '60px' : '260px',
          background: 'rgba(12, 16, 32, 0.85)',
          borderRight: '1px solid rgba(100, 120, 180, 0.12)',
          transition: 'width 0.3s ease',
        }}
      >
        {/* Left Icon Navigation */}
        <div className="w-[60px] border-r border-white/10 flex flex-col items-center py-4 flex-shrink-0"
          style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
        >
          {/* Logo */}
          <div className="w-10 h-10 rounded-xl backdrop-blur-md flex items-center justify-center mb-6"
            style={{
              background: 'linear-gradient(135deg, rgba(88, 166, 255, 0.2) 0%, rgba(88, 166, 255, 0.05) 100%)',
              border: '1px solid rgba(88, 166, 255, 0.2)',
              boxShadow: '0 0 20px rgba(88, 166, 255, 0.15)',
            }}
          >
            <MessageSquare className="w-5 h-5 text-accent-blue" />
          </div>

          {/* Nav Icons */}
          <nav className="flex flex-col gap-2">
            {navItems.map((item) => {
              const Icon = iconMap[item.icon];
              return (
                <button
                  key={item.id}
                  className="relative w-10 h-10 rounded-xl flex items-center justify-center text-text-secondary hover:text-text-primary hover:bg-white/5 transition-all duration-150 group"
                  title={item.label}
                >
                  <Icon className="w-5 h-5" />
                  {item.hasNotification && (
                    <span className="absolute top-1 right-1 w-2 h-2 bg-accent-blue rounded-full shadow-lg shadow-accent-blue/50" />
                  )}
                  
                  {/* Tooltip */}
                  <span className="absolute left-full ml-2 px-2 py-1 rounded-lg opacity-0 group-hover:opacity-100 pointer-events-none whitespace-nowrap z-50 transition-opacity duration-150 text-xs"
                    style={{
                      background: 'rgba(15, 22, 40, 0.9)',
                      backdropFilter: 'blur(8px)',
                      border: '1px solid rgba(100, 120, 180, 0.2)',
                      color: '#F0F6FC',
                    }}
                  >
                    {item.label}
                  </span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Right Content Panel */}
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
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/10"
                style={{ borderColor: 'rgba(100, 120, 180, 0.1)' }}
              >
                <h2 className="text-lg font-semibold text-text-primary">Chats</h2>
                <button 
                  onClick={() => setIsCollapsed(true)}
                  className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary hover:text-text-primary transition-all duration-150 hover:bg-white/5"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
              </div>

              {/* New Chat Button */}
              <div className="px-4 py-3">
                <button
                  onClick={onNewChat}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-text-primary text-sm font-medium transition-all duration-150 hover:scale-[1.02]"
                  style={{
                    background: 'linear-gradient(135deg, rgba(88, 166, 255, 0.15) 0%, rgba(88, 166, 255, 0.05) 100%)',
                    border: '1px solid rgba(88, 166, 255, 0.2)',
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
                    placeholder="Search chats..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 rounded-xl text-sm text-text-primary placeholder:text-text-muted focus:outline-none transition-all duration-150"
                    style={{
                      background: 'rgba(10, 14, 28, 0.6)',
                      border: '1px solid rgba(100, 120, 180, 0.2)',
                    }}
                  />
                </div>
              </div>

              {/* Chat List */}
              <div className="flex-1 overflow-y-auto scrollbar-dark">
                {filteredChats.length > 0 && (
                  <div className="px-4 py-2">
                    <h3 className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">
                      Today
                    </h3>
                    <div className="space-y-1">
                      {filteredChats.map((chat) => (
                        <button
                          key={chat.id}
                          onClick={() => onChatSelect?.(chat.id)}
                          className="w-full text-left px-3 py-2 rounded-xl text-sm transition-all duration-150"
                          style={{
                            background: chat.isActive || activeChatId === chat.id
                              ? 'rgba(88, 166, 255, 0.1)' 
                              : 'transparent',
                            border: chat.isActive || activeChatId === chat.id
                              ? '1px solid rgba(88, 166, 255, 0.2)'
                              : '1px solid transparent',
                            color: chat.isActive || activeChatId === chat.id ? '#F0F6FC' : '#A0A8B8',
                          }}
                        >
                          <span className="truncate block">{chat.title}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.aside>

      {/* Expand Button (outside sidebar, fixed position) */}
      <AnimatePresence>
        {isCollapsed && (
          <motion.button
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -10 }}
            transition={{ duration: 0.2 }}
            onClick={() => setIsCollapsed(false)}
            className="fixed left-[60px] top-1/2 -translate-y-1/2 z-50 w-6 h-12 rounded-r-lg flex items-center justify-center text-text-secondary hover:text-text-primary transition-all duration-150 hover:bg-white/10"
            style={{
              background: 'rgba(15, 22, 40, 0.95)',
              border: '1px solid rgba(100, 120, 180, 0.3)',
              borderLeft: 'none',
              boxShadow: '4px 0 12px rgba(0, 0, 0, 0.3)',
            }}
          >
            <ChevronRight className="w-4 h-4" />
          </motion.button>
        )}
      </AnimatePresence>
    </>
  );
}

export default Sidebar;
