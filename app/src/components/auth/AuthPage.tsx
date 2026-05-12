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
      style={{
        background: `
          radial-gradient(ellipse at 16% 12%, rgba(66, 133, 244, 0.10) 0%, transparent 38%),
          radial-gradient(ellipse at 86% 8%, rgba(52, 168, 83, 0.08) 0%, transparent 34%),
          linear-gradient(180deg, #f8fafd 0%, #eef3fb 100%)
        `,
      }}
    >
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] }}
        className="w-full max-w-md"
      >
        {/* Logo / Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-3xl mb-4 bg-white"
            style={{
              border: '1px solid #e8eaed',
              boxShadow: '0 8px 24px rgba(60, 64, 67, 0.12)',
            }}
          >
            <Shield className="w-8 h-8 text-accent-blue" />
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-text-primary">gireng</h1>
          <p className="text-sm text-text-secondary mt-1">Malware Analysis Platform</p>
        </div>

        {/* Card */}
        <div className="rounded-3xl bg-white p-8"
          style={{
            border: '1px solid #e8eaed',
            boxShadow: '0 8px 24px rgba(60, 64, 67, 0.12), 0 2px 6px rgba(60, 64, 67, 0.08)',
          }}
        >
          {/* Tabs */}
          <div className="flex mb-6 rounded-full overflow-hidden border border-border-default p-1"
            style={{ background: '#f8fafd' }}
          >
            <button
              className={`flex-1 py-2.5 text-sm font-medium transition-all ${
                isLogin
                  ? 'text-accent-blue bg-blue-50 rounded-full'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
              onClick={() => { setIsLogin(true); setError(''); }}
            >
              Sign In
            </button>
            <button
              className={`flex-1 py-2.5 text-sm font-medium transition-all ${
                !isLogin
                  ? 'text-accent-blue bg-blue-50 rounded-full'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
              onClick={() => { setIsLogin(false); setError(''); }}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="block text-xs text-text-secondary uppercase tracking-wider mb-1.5">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full px-4 py-2.5 rounded-xl text-sm text-text-primary placeholder:text-text-muted outline-none transition-all focus:ring-4 focus:ring-blue-100"
                style={{
                  background: '#ffffff',
                  border: '1px solid #dadce0',
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
                <label className="block text-xs text-text-secondary uppercase tracking-wider mb-1.5">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  className="w-full px-4 py-2.5 rounded-xl text-sm text-text-primary placeholder:text-text-muted outline-none transition-all focus:ring-4 focus:ring-blue-100"
                  style={{
                    background: '#ffffff',
                    border: '1px solid #dadce0',
                  }}
                  placeholder="analyst42"
                />
              </motion.div>
            )}

            {/* Password */}
            <div>
              <label className="block text-xs text-text-secondary uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete={isLogin ? 'current-password' : 'new-password'}
                  className="w-full px-4 py-2.5 pr-10 rounded-xl text-sm text-text-primary placeholder:text-text-muted outline-none transition-all focus:ring-4 focus:ring-blue-100"
                  style={{
                    background: '#ffffff',
                    border: '1px solid #dadce0',
                  }}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
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
                className="text-sm text-accent-red bg-red-50 border border-red-100 rounded-xl px-3 py-2"
              >
                {error}
              </motion.div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-full text-sm font-medium text-white transition-all disabled:opacity-50 flex items-center justify-center gap-2 shadow-glass"
              style={{
                background: loading
                  ? '#aecbfa'
                  : '#1a73e8',
                border: '1px solid #1a73e8',
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
        <p className="text-center text-xs text-text-muted mt-4">
          {isLogin ? (
            <>Don&apos;t have an account?{' '}
              <button onClick={() => setIsLogin(false)} className="text-accent-blue hover:underline">Register</button>
            </>
          ) : (
            <>Already have an account?{' '}
              <button onClick={() => setIsLogin(true)} className="text-accent-blue hover:underline">Sign In</button>
            </>
          )}
        </p>
      </motion.div>
    </div>
  );
}
