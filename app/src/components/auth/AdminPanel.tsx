import { useState, useEffect, useCallback } from 'react';
import { ArrowLeft, Shield, Trash2, UserCheck, UserX, RefreshCw, KeyRound, Save } from 'lucide-react';
import { apiGetUsers, apiUpdateUserRole, apiToggleUserActive, apiDeleteUser, apiResetPassword, apiUpdateQuota } from '@/lib/api';
import type { User } from '@/types';

interface AdminPanelProps {
  onBack: () => void;
  currentUserId: string;
}

const ROLES = ['admin', 'user', 'guest'] as const;

const roleBadge: Record<string, string> = {
  admin: 'bg-red-50 text-accent-red border-red-100',
  user: 'bg-blue-50 text-accent-blue border-blue-100',
  guest: 'bg-slate-100 text-text-secondary border-slate-200',
};

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export function AdminPanel({ onBack, currentUserId }: AdminPanelProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  // Quota editing state: { userId: editedValue }
  const [quotaEdits, setQuotaEdits] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await apiGetUsers();
      setUsers(Array.isArray(data) ? data : data.items ?? []);
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Failed to load users'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const flash = (msg: string) => { setSuccess(msg); setTimeout(() => setSuccess(''), 3000); };

  const handleRoleChange = async (id: string, role: string) => {
    setActionLoading(id);
    try {
      await apiUpdateUserRole(id, role);
      setUsers(prev => prev.map(u => u.id === id ? { ...u, role: role as User['role'] } : u));
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Failed to update role'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleToggleActive = async (u: User) => {
    setActionLoading(u.id);
    try {
      await apiToggleUserActive(u.id);
      setUsers(prev => prev.map(x => x.id === u.id ? { ...x, is_active: !x.is_active } : x));
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Failed to update user status'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (u: User) => {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return;
    setActionLoading(u.id);
    try {
      await apiDeleteUser(u.id);
      setUsers(prev => prev.filter(x => x.id !== u.id));
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Failed to delete user'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleResetPassword = async (u: User) => {
    const pw = prompt(`Enter new password for "${u.username}" (min 4 chars):`);
    if (!pw) return;
    if (pw.length < 4) { setError('Password must be at least 4 characters'); return; }
    setActionLoading(u.id);
    try {
      await apiResetPassword(u.id, pw);
      flash(`Password reset for ${u.username}`);
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Failed to reset password'));
    } finally {
      setActionLoading(null);
    }
  };

  const handleQuotaSave = async (u: User) => {
    const raw = quotaEdits[u.id];
    if (raw === undefined) return;
    const val = parseInt(raw, 10);
    if (isNaN(val) || val < -1) { setError('Quota must be -1 (unlimited) or >= 0'); return; }
    setActionLoading(u.id);
    try {
      await apiUpdateQuota(u.id, val);
      setUsers(prev => prev.map(x => x.id === u.id ? { ...x, quota: val } : x));
      setQuotaEdits(prev => { const n = { ...prev }; delete n[u.id]; return n; });
      flash(`Quota updated for ${u.username}`);
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Failed to update quota'));
    } finally {
      setActionLoading(null);
    }
  };

  const formatQuota = (q?: number) => (q === undefined ? '10' : q === -1 ? '∞' : String(q));

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-border-subtle">
        <button onClick={onBack} className="p-1.5 rounded-full hover:bg-bg-hover transition-colors">
          <ArrowLeft className="w-5 h-5 text-text-secondary" />
        </button>
        <Shield className="w-5 h-5 text-accent-red" />
        <h2 className="text-lg font-semibold text-text-primary">User Management</h2>
        <span className="text-xs text-text-muted ml-auto">{users.length} users</span>
        <button onClick={load} className="p-1.5 rounded-full hover:bg-bg-hover transition-colors" title="Refresh">
          <RefreshCw className={`w-4 h-4 text-text-muted ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {error && (
        <div className="mx-4 mt-3 px-3 py-2 rounded-xl bg-red-50 border border-red-100 text-accent-red text-sm">
          {error}
        </div>
      )}
      {success && (
        <div className="mx-4 mt-3 px-3 py-2 rounded-xl bg-green-50 border border-green-100 text-accent-green text-sm">
          {success}
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-auto p-4">
        {loading && users.length === 0 ? (
          <div className="flex items-center justify-center h-40 text-text-muted">Loading…</div>
        ) : (
          <table className="w-full text-sm bg-white rounded-2xl overflow-hidden">
            <thead>
              <tr className="text-text-muted text-xs uppercase tracking-wider border-b border-border-subtle bg-bg-secondary">
                <th className="text-left py-2 px-2">User</th>
                <th className="text-left py-2 px-2">Email</th>
                <th className="text-left py-2 px-2">Role</th>
                <th className="text-center py-2 px-2">Status</th>
                <th className="text-center py-2 px-2">Quota</th>
                <th className="text-right py-2 px-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => {
                const isSelf = u.id === currentUserId;
                const busy = actionLoading === u.id;
                const quotaDirty = quotaEdits[u.id] !== undefined;
                return (
                  <tr
                    key={u.id}
                    className="border-b border-border-subtle hover:bg-bg-hover transition-colors"
                  >
                    <td className="py-2.5 px-2">
                      <span className="text-text-primary">{u.username}</span>
                      {isSelf && <span className="ml-1.5 text-[10px] text-text-muted">(you)</span>}
                    </td>
                    <td className="py-2.5 px-2 text-text-secondary">{u.email}</td>
                    <td className="py-2.5 px-2">
                      {isSelf ? (
                        <span className={`text-xs px-2 py-0.5 rounded border ${roleBadge[u.role]}`}>
                          {u.role}
                        </span>
                      ) : (
                        <select
                          value={u.role}
                          disabled={busy}
                          onChange={e => handleRoleChange(u.id, e.target.value)}
                          className="text-xs rounded-full px-2 py-1 bg-white border border-border-default text-text-secondary focus:outline-none focus:border-accent-blue"
                        >
                          {ROLES.map(r => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                      )}
                    </td>
                    <td className="py-2.5 px-2 text-center">
                      {u.is_active ? (
                        <span className="text-xs text-accent-green">Active</span>
                      ) : (
                        <span className="text-xs text-accent-red">Disabled</span>
                      )}
                    </td>
                    <td className="py-2.5 px-2 text-center">
                      <div className="flex items-center justify-center gap-1">
                        <span className="text-xs text-text-secondary">
                          {u.analysis_count ?? 0}/{formatQuota(u.quota)}
                        </span>
                        {!isSelf && (
                          <>
                            <input
                              type="number"
                              min={-1}
                              value={quotaEdits[u.id] ?? String(u.quota ?? 10)}
                              onChange={e => setQuotaEdits(prev => ({ ...prev, [u.id]: e.target.value }))}
                              className="w-14 text-xs rounded-lg px-1.5 py-0.5 bg-white border border-border-default text-text-secondary focus:outline-none focus:border-accent-blue text-center"
                              title="Quota (-1 = unlimited)"
                            />
                            {quotaDirty && (
                              <button
                                onClick={() => handleQuotaSave(u)}
                                disabled={busy}
                                className="p-0.5 rounded-full hover:bg-bg-hover transition-colors disabled:opacity-30"
                                title="Save quota"
                              >
                                <Save className="w-3.5 h-3.5 text-accent-green" />
                              </button>
                            )}
                          </>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center justify-end gap-1">
                        {!isSelf && (
                          <>
                            <button
                              onClick={() => handleResetPassword(u)}
                              disabled={busy}
                              className="p-1.5 rounded-full hover:bg-bg-hover transition-colors disabled:opacity-30"
                              title="Reset password"
                            >
                              <KeyRound className="w-4 h-4 text-accent-blue" />
                            </button>
                            <button
                              onClick={() => handleToggleActive(u)}
                              disabled={busy}
                              className="p-1.5 rounded-full hover:bg-bg-hover transition-colors disabled:opacity-30"
                              title={u.is_active ? 'Deactivate' : 'Activate'}
                            >
                              {u.is_active
                                ? <UserX className="w-4 h-4 text-accent-orange" />
                                : <UserCheck className="w-4 h-4 text-accent-green" />}
                            </button>
                            <button
                              onClick={() => handleDelete(u)}
                              disabled={busy}
                              className="p-1.5 rounded-full hover:bg-red-50 transition-colors disabled:opacity-30"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4 text-accent-red" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
