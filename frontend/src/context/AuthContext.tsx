import React, { createContext, useContext, useEffect, useState } from "react";
import { AuthStatus, User, UserSetupPayload } from "../types";
import { api } from "../services/api";
import { useForensicStore } from "../store/useForensicStore";

interface AuthContextType {
  user: User | null;
  token: string | null;
  isInitialized: boolean;
  isLoading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  setupFirstBoot: (payload: UserSetupPayload) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem("forensicops_token"));
  const [isInitialized, setIsInitialized] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const { currentCaseId, setCaseId } = useForensicStore();

  const checkStatusAndSession = async () => {
    setIsLoading(true);
    try {
      // Security Enforcement: purge persistent localStorage tokens to guarantee credential challenge on fresh sessions
      localStorage.removeItem("forensicops_token");

      const statusRes = await api.getAuthStatus();
      setIsInitialized(statusRes.initialized);

      if (!statusRes.initialized) {
        // Needs first-boot setup
        setUser(null);
        setToken(null);
        sessionStorage.removeItem("forensicops_token");
        setIsLoading(false);
        return;
      }

      const storedToken = sessionStorage.getItem("forensicops_token");
      if (storedToken) {
        try {
          const me = await api.getMe();
          setUser(me);
          setToken(storedToken);
        } catch {
          // Token invalid or expired
          sessionStorage.removeItem("forensicops_token");
          setToken(null);
          setUser(null);
        }
      } else {
        setUser(null);
        setToken(null);
      }
    } catch (err: any) {
      console.warn("Auth initialization check:", err.message);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkStatusAndSession();
  }, []);

  const login = async (username: string, password: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.login({ username, password });
      sessionStorage.setItem("forensicops_token", res.access_token);
      setToken(res.access_token);
      setUser(res.user);
      setIsInitialized(true);
    } catch (err: any) {
      setError(err.message || "Authentication failed");
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const setupFirstBoot = async (payload: UserSetupPayload) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.setupFirstBoot(payload);
      sessionStorage.setItem("forensicops_token", res.access_token);
      setToken(res.access_token);
      setUser(res.user);
      setIsInitialized(true);
    } catch (err: any) {
      setError(err.message || "First-boot setup failed");
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    sessionStorage.removeItem("forensicops_token");
    localStorage.removeItem("forensicops_token");
    setToken(null);
    setUser(null);
  };

  const refreshUser = async () => {
    if (!token) return;
    try {
      const me = await api.getMe();
      setUser(me);
    } catch {
      logout();
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isInitialized,
        isLoading,
        error,
        login,
        setupFirstBoot,
        logout,
        refreshUser,
        clearError: () => setError(null),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
