import { createContext, useContext, useState, useCallback, type ReactNode } from "react";
import api from "./api";

interface User {
  id?: number;
  username: string;
  full_name?: string;
  job_title?: string;
  contact_info?: string;
  default_shift?: string;
  role?: string;
}

interface AuthContextType {
  user: User | null;
  token: string;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
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
  }, []);

  const logout = useCallback(() => {
    api.post("/auth/logout", null, { params: { username: user?.username } }).catch(() => {});
    sessionStorage.removeItem("noc_token");
    sessionStorage.removeItem("noc_user");
    setUser(null);
    setToken("");
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
