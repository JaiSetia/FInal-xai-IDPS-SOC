import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, onTokenChange, setToken } from "./api/client";

export type Role = "analyst" | "admin";
export interface Me {
  id: number;
  username: string;
  role: Role;
}

interface AuthState {
  me: Me | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState<boolean>(Boolean(getToken()));

  const loadMe = useCallback(async () => {
    if (!getToken()) {
      setMe(null);
      setLoading(false);
      return;
    }
    try {
      setMe(await api<Me>("/auth/me"));
    } catch {
      setToken(null);
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadMe();
    // Any 401 clears the token (see api/client.ts); that sends the user back to login.
    return onTokenChange(() => {
      if (!getToken()) setMe(null);
    });
  }, [loadMe]);

  const login = useCallback(async (username: string, password: string) => {
    const res = await api<{ access_token: string }>("/auth/login", {
      method: "POST",
      json: { username, password },
    });
    setToken(res.access_token);
    await loadMe();
  }, [loadMe]);

  const logout = useCallback(() => {
    setToken(null);
    setMe(null);
  }, []);

  return <AuthContext.Provider value={{ me, loading, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
