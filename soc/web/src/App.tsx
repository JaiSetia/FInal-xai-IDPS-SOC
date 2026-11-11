import { lazy, Suspense } from "react";
import { Navigate, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import ErrorBoundary from "./components/ErrorBoundary";
import Actions from "./pages/Actions";
import Admin from "./pages/Admin";
import AlertDetail from "./pages/AlertDetail";
import Alerts from "./pages/Alerts";
import Blocks from "./pages/Blocks";
import CaseDetail from "./pages/CaseDetail";
import Cases from "./pages/Cases";
import Login from "./pages/Login";

// The charting library is large, so the metrics page loads on demand.
const Metrics = lazy(() => import("./pages/Metrics"));

export default function App() {
  const { me, loading, logout } = useAuth();
  const location = useLocation();

  if (loading) return <p className="muted" style={{ padding: 24 }}>Loading…</p>;
  if (!me) return <Login />;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">IDPS SOC<small>XAI intrusion detection</small></div>
        <nav className="nav" aria-label="Main">
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/actions">Actions</NavLink>
          <NavLink to="/blocks">Blocks</NavLink>
          <NavLink to="/cases">Cases</NavLink>
          <NavLink to="/metrics">Metrics</NavLink>
          {me.role === "admin" && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <div className="spacer" />
        <div className="userbox">
          Signed in as <b>{me.username}</b> ({me.role})
          <div><button style={{ marginTop: 6 }} onClick={logout}>Sign out</button></div>
        </div>
      </aside>
      <main>
        <ErrorBoundary resetKey={location.pathname}>
        <Routes>
          <Route path="/" element={<Navigate to="/alerts" replace />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/actions" element={<Actions />} />
          <Route path="/blocks" element={<Blocks />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/cases/:id" element={<CaseDetail />} />
          <Route path="/metrics" element={<Suspense fallback={<p className="muted">Loading…</p>}><Metrics /></Suspense>} />
          {me.role === "admin" && <Route path="/admin" element={<Admin />} />}
          <Route path="*" element={<p className="muted">Page not found.</p>} />
        </Routes>
        </ErrorBoundary>
      </main>
    </div>
  );
}
