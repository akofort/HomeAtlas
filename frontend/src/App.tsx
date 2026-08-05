import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ApiError, api, type User } from "./lib/api";
import LoginPage from "./pages/LoginPage";
import MfaEnrollPage from "./pages/MfaEnrollPage";
import SetupPage from "./pages/SetupPage";
import DashboardPage from "./pages/DashboardPage";
import InventoryPage from "./pages/InventoryPage";
import SystemDetailPage from "./pages/SystemDetailPage";
import AccessLogPage from "./pages/AccessLogPage";
import AccountsPage from "./pages/AccountsPage";
import DocsPage from "./pages/DocsPage";
import PlanPage from "./pages/PlanPage";
import ChatPage from "./pages/ChatPage";
import ScanPage from "./pages/ScanPage";
import SettingsPage from "./pages/SettingsPage";
import UsersPage from "./pages/UsersPage";

interface AuthState {
  user: User | null;
  isAdmin: boolean;
  setUser: (user: User | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  user: null,
  isAdmin: false,
  setUser: () => {},
  logout: async () => {},
});

export const useAuth = () => useContext(AuthContext);

const NAV = [
  { to: "/", label: "Übersicht", icon: "🏠", end: true },
  { to: "/geraete", label: "Geräte", icon: "🖧" },
  { to: "/plan", label: "Netzplan", icon: "🗺️" },
  { to: "/zugaenge", label: "Zugänge", icon: "🔑", adminOnly: true },
  { to: "/dokumentation", label: "Dokumentation", icon: "📘" },
  { to: "/assistent", label: "KI-Assistent", icon: "💬" },
  { to: "/scan", label: "Netzwerk-Scan", icon: "🔍", adminOnly: true },
  { to: "/benutzer", label: "Benutzer", icon: "👥", adminOnly: true },
  { to: "/protokoll", label: "Protokoll", icon: "📋", adminOnly: true },
  { to: "/einstellungen", label: "Einstellungen", icon: "⚙️" },
];

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [setupCompleted, setSetupCompleted] = useState(true);
  const location = useLocation();

  const refresh = useCallback(async () => {
    try {
      const [me, health] = await Promise.all([api.me(), api.health()]);
      setUser(me.user);
      setSetupCompleted(health.setupCompleted);
    } catch (error) {
      // A 401 is the normal "not logged in yet" case, not something to surface.
      if (!(error instanceof ApiError && error.status === 401)) console.error(error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
  }, []);

  if (loading) {
    return (
      <div className="centered">
        <span className="spinner" />
      </div>
    );
  }

  if (!user) return <LoginPage onLoggedIn={() => void refresh()} />;

  const isAdmin = user.role === "ADMIN";

  // The second factor is mandatory (the backend enforces this on every other route -- see
  // main.py's `current_user`); this is just the matching UI. Comes before the setup wizard below:
  // the account gets secured first, then the household gets configured.
  if (!user.totpEnabled) {
    return (
      <AuthContext.Provider value={{ user, isAdmin, setUser, logout }}>
        <MfaEnrollPage onDone={() => void refresh()} />
      </AuthContext.Provider>
    );
  }

  // First run: an admin lands in the wizard until the household basics are recorded. Members are
  // let through -- they can't complete it anyway, and locking them out of a working app is worse.
  if (!setupCompleted && isAdmin) {
    return (
      <AuthContext.Provider value={{ user, isAdmin, setUser, logout }}>
        <SetupPage onDone={() => void refresh()} />
      </AuthContext.Provider>
    );
  }

  return (
    <AuthContext.Provider value={{ user, isAdmin, setUser, logout }}>
      <div className="app">
        <nav className="sidebar">
          <div className="brand">
            <span className="brand-mark">🧭</span>
            <div>
              <div className="brand-name">HomeAtlas</div>
              <div className="brand-sub">Dein Zuhause, dokumentiert</div>
            </div>
          </div>
          {NAV.filter((item) => !item.adminOnly || isAdmin).map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className="nav-link">
              <span aria-hidden>{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
          <div className="sidebar-footer">
            <div>
              Angemeldet als <strong>{user.displayName || user.username}</strong>
            </div>
            <div className="muted">{isAdmin ? "Administrator" : "Mitglied (nur lesen)"}</div>
            <button className="secondary small" style={{ marginTop: 10 }} onClick={() => void logout()}>
              Abmelden
            </button>
          </div>
        </nav>

        <main className={`content${location.pathname === "/assistent" ? " content-chat" : ""}`}>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/geraete" element={<InventoryPage />} />
            <Route path="/geraete/:id" element={<SystemDetailPage />} />
            {isAdmin && <Route path="/zugaenge" element={<AccountsPage />} />}
            <Route path="/dokumentation" element={<DocsPage />} />
            <Route path="/dokumentation/:slug" element={<DocsPage />} />
            <Route path="/assistent" element={<ChatPage />} />
            {isAdmin && <Route path="/scan" element={<ScanPage />} />}
            <Route path="/plan" element={<PlanPage />} />
            {isAdmin && <Route path="/benutzer" element={<UsersPage />} />}
            {isAdmin && <Route path="/protokoll" element={<AccessLogPage />} />}
            <Route path="/einstellungen" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </AuthContext.Provider>
  );
}
