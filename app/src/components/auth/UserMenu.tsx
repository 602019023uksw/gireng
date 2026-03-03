import { useState, useRef, useEffect } from 'react';
import { LogOut, User, ChevronDown, Settings } from 'lucide-react';
import type { User as UserType } from '@/types';

interface UserMenuProps {
  user: UserType;
  onLogout: () => void;
  onAdminPanel?: () => void;
}

const roleBadgeColors: Record<string, string> = {
  admin: 'bg-red-500/20 text-red-400 border-red-500/30',
  user: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  guest: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

export function UserMenu({ user, onLogout, onAdminPanel }: UserMenuProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-all hover:bg-white/5"
        style={{ border: '1px solid rgba(100, 120, 180, 0.15)' }}
      >
        <div className="w-6 h-6 rounded-full flex items-center justify-center bg-blue-500/20">
          <User className="w-3.5 h-3.5 text-blue-400" />
        </div>
        <span className="text-gray-300 max-w-[120px] truncate">{user.username}</span>
        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${roleBadgeColors[user.role] || roleBadgeColors.guest}`}>
          {user.role}
        </span>
        <ChevronDown className={`w-3.5 h-3.5 text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          className="absolute right-0 top-full mt-1 w-48 rounded-lg py-1 z-50"
          style={{
            background: 'rgba(20, 28, 50, 0.95)',
            border: '1px solid rgba(100, 120, 180, 0.2)',
            boxShadow: '0 8px 32px -4px rgba(0,0,0,0.5)',
          }}
        >
          <div className="px-3 py-2 border-b border-white/5">
            <p className="text-xs text-gray-400 truncate">{user.email}</p>
          </div>

          {user.role === 'admin' && onAdminPanel && (
            <button
              onClick={() => { setOpen(false); onAdminPanel(); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-300 hover:bg-white/5 transition-colors"
            >
              <Settings className="w-4 h-4 text-gray-500" />
              Admin Panel
            </button>
          )}

          <button
            onClick={() => { setOpen(false); onLogout(); }}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      )}
    </div>
  );
}
