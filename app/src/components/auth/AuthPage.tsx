import { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Eye, EyeOff, LogIn, UserPlus } from 'lucide-react';

interface AuthPageProps {
  onLogin: (email: string, password: string) => Promise<void>;
  onRegister: (email: string, username: string, password: string) => Promise<void>;
}

export function AuthPage({ onLogin, onRegister }: AuthPageProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (isLogin) {
        await onLogin(email, password);
      } else {
        if (!username.trim()) {
          setError('Username is required');
          setLoading(false);
          return;
        }
        await onRegister(email, username, password);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4"
      style={{ background: 'linear-gradient(135deg, #0a0e1a 0%, #111827 50%, #0f172a 100%)' }}
    >
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] }}
        className="w-full max-w-md"
      >
        {/* Logo / Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4"
            style={{
              background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.2))',
              border: '1px solid rgba(100, 120, 180, 0.3)',
            }}
          >
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
          <h1 className="text-2xl font-bold text-white">gireng</h1>
          <p className="text-sm text-gray-400 mt-1">Malware Analysis Platform</p>
        </div>

        {/* Card */}
        <div className="backdrop-blur-xl rounded-2xl p-8"
          style={{
            background: 'linear-gradient(135deg, rgba(20, 28, 50, 0.8) 0%, rgba(15, 20, 35, 0.6) 100%)',
            border: '1px solid rgba(100, 120, 180, 0.2)',
            boxShadow: '0 8px 32px -4px rgba(0, 0, 0, 0.5)',
          }}
        >
          {/* Tabs */}
          <div className="flex mb-6 rounded-lg overflow-hidden"
            style={{ background: 'rgba(255,255,255,0.05)' }}
          >
            <button
              className={`flex-1 py-2.5 text-sm font-medium transition-all ${
                isLogin
                  ? 'text-white bg-blue-600/30'
                  : 'text-gray-400 hover:text-gray-300'
              }`}
              onClick={() => { setIsLogin(true); setError(''); }}
            >
              Sign In
            </button>
            <button
              className={`flex-1 py-2.5 text-sm font-medium transition-all ${
                !isLogin
                  ? 'text-white bg-blue-600/30'
                  : 'text-gray-400 hover:text-gray-300'
              }`}
              onClick={() => { setIsLogin(false); setError(''); }}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1.5">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full px-4 py-2.5 rounded-lg text-sm text-white placeholder-gray-500 outline-none transition-all focus:ring-2 focus:ring-blue-500/40"
                style={{
                  background: 'rgba(255,255,255,0.06)',
                  border: '1px solid rgba(100, 120, 180, 0.2)',
                }}
                placeholder="you@example.com"
              />
            </div>

            {/* Username (register only) */}
            {!isLogin && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
              >
                <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1.5">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  className="w-full px-4 py-2.5 rounded-lg text-sm text-white placeholder-gray-500 outline-none transition-all focus:ring-2 focus:ring-blue-500/40"
                  style={{
                    background: 'rgba(255,255,255,0.06)',
                    border: '1px solid rgba(100, 120, 180, 0.2)',
                  }}
                  placeholder="analyst42"
                />
              </motion.div>
            )}

            {/* Password */}
            <div>
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete={isLogin ? 'current-password' : 'new-password'}
                  className="w-full px-4 py-2.5 pr-10 rounded-lg text-sm text-white placeholder-gray-500 outline-none transition-all focus:ring-2 focus:ring-blue-500/40"
                  style={{
                    background: 'rgba(255,255,255,0.06)',
                    border: '1px solid rgba(100, 120, 180, 0.2)',
                  }}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2"
              >
                {error}
              </motion.div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg text-sm font-medium text-white transition-all disabled:opacity-50 flex items-center justify-center gap-2"
              style={{
                background: loading
                  ? 'rgba(59, 130, 246, 0.3)'
                  : 'linear-gradient(135deg, rgba(59, 130, 246, 0.6), rgba(139, 92, 246, 0.6))',
                border: '1px solid rgba(59, 130, 246, 0.3)',
              }}
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : isLogin ? (
                <>
                  <LogIn className="w-4 h-4" />
                  Sign In
                </>
              ) : (
                <>
                  <UserPlus className="w-4 h-4" />
                  Create Account
                </>
              )}
            </button>
          </form>
        </div>

        {/* Footer hint */}
        <p className="text-center text-xs text-gray-500 mt-4">
          {isLogin ? (
            <>Don&apos;t have an account?{' '}
              <button onClick={() => setIsLogin(false)} className="text-blue-400 hover:underline">Register</button>
            </>
          ) : (
            <>Already have an account?{' '}
              <button onClick={() => setIsLogin(true)} className="text-blue-400 hover:underline">Sign In</button>
            </>
          )}
        </p>
      </motion.div>
    </div>
  );
}
