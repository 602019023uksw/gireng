import { useState, useRef, useEffect } from 'react';
import { LogOut, User, ChevronDown, Settings } from 'lucide-react';
import type { User as UserType } from '@/types';

interface UserMenuProps {
  user: UserType;
  onLogout: () => void;
  onAdminPanel?: () => void;
}

const roleBadgeColors: Record<string, string> = {
  admin: 'bg-red-50 text-accent-red border-red-100',
  user: 'bg-blue-50 text-accent-blue border-blue-100',
  guest: 'bg-slate-100 text-text-secondary border-slate-200',
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
        className="flex items-center gap-2 px-3 py-1.5 rounded-full text-sm transition-all hover:bg-bg-hover"
        style={{ border: '1px solid #dadce0' }}
      >
        <div className="w-6 h-6 rounded-full flex items-center justify-center bg-blue-50">
          <User className="w-3.5 h-3.5 text-accent-blue" />
        </div>
        <span className="text-text-primary max-w-[120px] truncate">{user.username}</span>
        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${roleBadgeColors[user.role] || roleBadgeColors.guest}`}>
          {user.role}
        </span>
        <ChevronDown className={`w-3.5 h-3.5 text-text-muted transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          className="absolute right-0 top-full mt-2 w-48 rounded-2xl py-1 z-50 bg-white"
          style={{
            border: '1px solid #e8eaed',
            boxShadow: '0 8px 24px rgba(60, 64, 67, 0.16)',
          }}
        >
          <div className="px-3 py-2 border-b border-border-subtle">
            <p className="text-xs text-text-secondary truncate">{user.email}</p>
            {user.quota !== undefined && (
              <p className="text-[10px] text-text-muted mt-0.5">
                Analyses: {user.analysis_count ?? 0}/{user.quota === -1 ? '∞' : user.quota}
              </p>
            )}
          </div>

          {user.role === 'admin' && onAdminPanel && (
            <button
              onClick={() => { setOpen(false); onAdminPanel(); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors"
            >
              <Settings className="w-4 h-4 text-text-muted" />
              Admin Panel
            </button>
          )}

          <button
            onClick={() => { setOpen(false); onLogout(); }}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-accent-red hover:bg-red-50 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      )}
    </div>
  );
}
