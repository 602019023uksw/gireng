import { useState, useEffect, useCallback } from 'react';
import { ArrowLeft, Shield, Trash2, UserCheck, UserX, RefreshCw } from 'lucide-react';
import { apiGetUsers, apiUpdateUserRole, apiToggleUserActive, apiDeleteUser } from '@/lib/api';
import type { User } from '@/types';

interface AdminPanelProps {
  onBack: () => void;
  currentUserId: string;
}

const ROLES = ['admin', 'user', 'guest'] as const;

const roleBadge: Record<string, string> = {
  admin: 'bg-red-500/20 text-red-400 border-red-500/30',
  user: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  guest: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

export function AdminPanel({ onBack, currentUserId }: AdminPanelProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await apiGetUsers();
      setUsers(Array.isArray(data) ? data : data.items ?? []);
    } catch (e: any) {
      setError(e.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleRoleChange = async (id: string, role: string) => {
    setActionLoading(id);
    try {
      await apiUpdateUserRole(id, role);
      setUsers(prev => prev.map(u => u.id === id ? { ...u, role: role as User['role'] } : u));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleToggleActive = async (u: User) => {
    setActionLoading(u.id);
    try {
      await apiToggleUserActive(u.id);
      setUsers(prev => prev.map(x => x.id === u.id ? { ...x, is_active: !x.is_active } : x));
    } catch (e: any) {
      setError(e.message);
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
    } catch (e: any) {
      setError(e.message);
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-white/5">
        <button onClick={onBack} className="p-1.5 rounded-lg hover:bg-white/5 transition-colors">
          <ArrowLeft className="w-5 h-5 text-gray-400" />
        </button>
        <Shield className="w-5 h-5 text-red-400" />
        <h2 className="text-lg font-semibold text-gray-200">User Management</h2>
        <span className="text-xs text-gray-500 ml-auto">{users.length} users</span>
        <button onClick={load} className="p-1.5 rounded-lg hover:bg-white/5 transition-colors" title="Refresh">
          <RefreshCw className={`w-4 h-4 text-gray-500 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {error && (
        <div className="mx-4 mt-3 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-auto p-4">
        {loading && users.length === 0 ? (
          <div className="flex items-center justify-center h-40 text-gray-500">Loading…</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase tracking-wider border-b border-white/5">
                <th className="text-left py-2 px-2">User</th>
                <th className="text-left py-2 px-2">Email</th>
                <th className="text-left py-2 px-2">Role</th>
                <th className="text-center py-2 px-2">Status</th>
                <th className="text-right py-2 px-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => {
                const isSelf = u.id === currentUserId;
                const busy = actionLoading === u.id;
                return (
                  <tr
                    key={u.id}
                    className="border-b border-white/5 hover:bg-white/[0.02] transition-colors"
                  >
                    <td className="py-2.5 px-2">
                      <span className="text-gray-300">{u.username}</span>
                      {isSelf && <span className="ml-1.5 text-[10px] text-gray-600">(you)</span>}
                    </td>
                    <td className="py-2.5 px-2 text-gray-400">{u.email}</td>
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
                          className="text-xs rounded px-2 py-1 bg-transparent border border-white/10 text-gray-300 focus:outline-none focus:border-blue-500/40"
                        >
                          {ROLES.map(r => (
                            <option key={r} value={r} className="bg-[#141c32]">{r}</option>
                          ))}
                        </select>
                      )}
                    </td>
                    <td className="py-2.5 px-2 text-center">
                      {u.is_active ? (
                        <span className="text-xs text-green-400">Active</span>
                      ) : (
                        <span className="text-xs text-red-400">Disabled</span>
                      )}
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center justify-end gap-1">
                        {!isSelf && (
                          <>
                            <button
                              onClick={() => handleToggleActive(u)}
                              disabled={busy}
                              className="p-1.5 rounded hover:bg-white/5 transition-colors disabled:opacity-30"
                              title={u.is_active ? 'Deactivate' : 'Activate'}
                            >
                              {u.is_active
                                ? <UserX className="w-4 h-4 text-yellow-500" />
                                : <UserCheck className="w-4 h-4 text-green-500" />}
                            </button>
                            <button
                              onClick={() => handleDelete(u)}
                              disabled={busy}
                              className="p-1.5 rounded hover:bg-red-500/10 transition-colors disabled:opacity-30"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4 text-red-500" />
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
