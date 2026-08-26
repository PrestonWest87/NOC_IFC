import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from "react";
import api from "./api";
import axios from "axios";

interface User {
  id?: number;
  username: string;
  full_name?: string;
  job_title?: string;
  contact_info?: string;
  default_shift?: string;
  theme?: string;
  role?: string;
  allowed_pages?: string[];
  allowed_actions?: string[];
  allowed_site_types?: string[];
}

interface AuthContextType {
  user: User | null;
  token: string;
  login: (username: string, password: string) => Promise<User>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>(null!);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    const stored = sessionStorage.getItem("noc_user");
    return stored ? JSON.parse(stored) : null;
  });
  const [token, setToken] = useState(sessionStorage.getItem("noc_token") ?? "");

  const login = useCallback(async (username: string, password: string) => {
    const { data } = await api.post("/auth/login", { username, password });
    sessionStorage.setItem("noc_token", data.token);
    sessionStorage.setItem("noc_user", JSON.stringify(data.user));
    setUser(data.user);
    setToken(data.token);
    return data.user;
  }, []);

  const refreshUser = useCallback(async () => {
    const tok = sessionStorage.getItem("noc_token");
    if (!tok) return;
    try {
      const { data } = await api.get("/auth/me");
      sessionStorage.setItem("noc_user", JSON.stringify(data));
      setUser(data);
    } catch (error) {
      // A brief network/API failure must not log a user out. Only an explicit
      // authentication rejection means that the session is no longer valid.
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        sessionStorage.removeItem("noc_token");
        sessionStorage.removeItem("noc_user");
        setUser(null);
        setToken("");
      } else {
        console.warn("Unable to refresh authenticated user; retaining session", error);
      }
    }
  }, []);

  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
      setToken("");
    };
    window.addEventListener("noc:unauthorized", handleUnauthorized);
    refreshUser();
    return () => window.removeEventListener("noc:unauthorized", handleUnauthorized);
  }, [refreshUser]);

  const logout = useCallback(() => {
    api.post("/auth/logout").catch(() => {});
    sessionStorage.removeItem("noc_token");
    sessionStorage.removeItem("noc_user");
    setUser(null);
    setToken("");
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, token, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
