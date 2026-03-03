import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { User } from '@/types';
import {
  apiLogin,
  apiRegister,
  apiGetMe,
  getStoredToken,
  setStoredToken,
  clearStoredToken,
} from '@/lib/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(getStoredToken());
  const [isLoading, setIsLoading] = useState(true);

  // On mount, validate existing token
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!token) {
        setIsLoading(false);
        return;
      }
      try {
        const me = await apiGetMe();
        if (!cancelled && me) {
          setUser(me as User);
        } else if (!cancelled) {
          // Token invalid — clear
          clearStoredToken();
          setToken(null);
        }
      } catch {
        if (!cancelled) {
          clearStoredToken();
          setToken(null);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const login = useCallback(async (email: string, password: string) => {
    const res = await apiLogin(email, password);
    setStoredToken(res.token);
    setToken(res.token);
    setUser(res.user as User);
  }, []);

  const register = useCallback(async (email: string, username: string, password: string) => {
    const res = await apiRegister(email, username, password);
    setStoredToken(res.token);
    setToken(res.token);
    setUser(res.user as User);
  }, []);

  const logout = useCallback(() => {
    clearStoredToken();
    setToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isAdmin: user?.role === 'admin',
        isLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
