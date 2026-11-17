import { useEffect, useState } from "react";
import "./App.css";

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  createdAt: string;
}

interface Session {
  id: string;
  userId: string;
  createdAt: string;
  expiresAt: string;
  isCurrent?: boolean;
  ipAddress?: string | null;
  userAgent?: string | null;
}

interface AuditLog {
  id: string;
  requestId: string | null;
  userId: string | null;
  action: string;
  resource: string;
  decision: "allow" | "deny";
  reason: string;
  ip: string | null;
  createdAt: string;
}

interface ApiResponse {
  endpoint: string;
  status: number;
  ok: boolean;
  durationMs: number;
  data: any;
}

interface ClockInfo {
  simulatedNow: string;
  timezone: string;
  inBusinessHours: boolean;
  isOverridden: boolean;
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [sessionsList, setSessionsList] = useState<Session[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [lastResponse, setLastResponse] = useState<ApiResponse | null>(null);
  const [clockInfo, setClockInfo] = useState<ClockInfo | null>(null);
  const [reauthWarning, setReauthWarning] = useState<{
    message: string;
    maxAgeSeconds: number;
    sessionAgeSeconds: number;
  } | null>(null);
  const [customEmail, setCustomEmail] = useState("");
  const [targetUserId, setTargetUserId] = useState("");
  const [loading, setLoading] = useState(true);

  // Fetch current server clock and business hours status
  const fetchClockInfo = async () => {
    try {
      const res = await fetch("/api/dev/clock");
      if (res.ok) {
        const data = await res.json();
        setClockInfo(data);
      }
    } catch {
      // Dev endpoint may be disabled in prod
    }
  };

  // Check current session on initial page load
  const checkSession = async () => {
    try {
      const res = await fetch("/api/me");
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setSession(data.session);
        fetchSessions();
        if (data.user?.role === "admin") {
          fetchAuditLogs();
        }
      } else {
        setUser(null);
        setSession(null);
      }
    } catch {
      setUser(null);
      setSession(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkSession();
    fetchClockInfo();
  }, []);

  // Fetch active sessions for the current user
  const fetchSessions = async () => {
    try {
      const res = await fetch("/api/sessions");
      if (res.ok) {
        const data = await res.json();
        setSessionsList(data.sessions || []);
      }
    } catch (err) {
      console.error("Failed to fetch sessions", err);
    }
  };

  // Fetch latest audit logs (admin only)
  const fetchAuditLogs = async () => {
    try {
      const res = await fetch("/api/admin/audit-logs");
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data.auditLogs || []);
      }
    } catch (err) {
      console.error("Failed to fetch audit logs", err);
    }
  };

  // Google OAuth sign-in flow
  const handleGoogleLogin = async (stepUp = false) => {
    try {
      const res = await fetch("/api/auth/sign-in/social", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: "google",
          callbackURL: window.location.origin,
          additionalParams: stepUp ? { prompt: "login" } : undefined,
        }),
      });
      const data = await res.json();
      if (data?.url) {
        window.location.href = data.url;
      }
    } catch (err) {
      console.error("Google sign in failed", err);
    }
  };

  // Dev fallback login (bypasses Google OAuth if offline/demoing)
  const handleDevLogin = async (
    role: "admin" | "manager" | "user",
    emailOverride?: string,
  ) => {
    const email = emailOverride || `${role}@workshop.local`;
    try {
      const res = await fetch("/api/dev/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, role, name: `Demo ${role}` }),
      });
      const data = await res.json();
      if (res.ok) {
        setUser(data.user);
        setSession(data.session);
        setReauthWarning(null);
        fetchSessions();
        fetchClockInfo();
        if (data.user.role === "admin") {
          fetchAuditLogs();
        }
      }
    } catch (err) {
      console.error("Dev login failed", err);
    }
  };

  // Sign out
  const handleLogout = async () => {
    await fetch("/api/auth/sign-out", { method: "POST" });
    setUser(null);
    setSession(null);
    setSessionsList([]);
    setAuditLogs([]);
    setLastResponse(null);
    setReauthWarning(null);
  };

  // Generic endpoint caller that records status and JSON body
  const callApi = async (
    _name: string,
    method: string,
    url: string,
    body?: any,
  ) => {
    const start = performance.now();
    try {
      const res = await fetch(url, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const durationMs = Math.round(performance.now() - start);
      const data = await res.json().catch(() => null);

      setLastResponse({
        endpoint: `${method} ${url}`,
        status: res.status,
        ok: res.ok,
        durationMs,
        data,
      });

      // Handle Step-Up Auth requirement (403 REAUTH_REQUIRED)
      if (res.status === 403 && data?.code === "REAUTH_REQUIRED") {
        setReauthWarning({
          message: data.error,
          maxAgeSeconds: data.maxAgeSeconds,
          sessionAgeSeconds: data.sessionAgeSeconds,
        });
      } else if (res.ok) {
        setReauthWarning(null);
      }

      // Refresh background context
      if (url.includes("/sessions") || method === "DELETE") {
        fetchSessions();
      }
      if (user?.role === "admin") {
        fetchAuditLogs();
      }
    } catch (err: any) {
      setLastResponse({
        endpoint: `${method} ${url}`,
        status: 0,
        ok: false,
        durationMs: 0,
        data: { error: err.message },
      });
    }
  };

  // Dev Clock simulator controls
  const handleClockShift = async (offsetSeconds: number) => {
    await fetch("/api/dev/clock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ offsetSeconds }),
    });
    fetchClockInfo();
    checkSession();
  };

  const handleClockSetHour = async (setHour: number) => {
    await fetch("/api/dev/clock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ setHour }),
    });
    fetchClockInfo();
    checkSession();
  };

  const handleClockReset = async () => {
    await fetch("/api/dev/clock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reset: true }),
    });
    setReauthWarning(null);
    fetchClockInfo();
    checkSession();
  };

  if (loading) {
    return (
      <div className="dashboard-container">
        <p>Loading workshop session...</p>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      {/* Header */}
      <header className="dashboard-header">
        <div className="dashboard-title">
          <h1>Auth Workshop Test Dashboard</h1>
          <p>
            University Dev Club — Server-Side Sessions, OIDC, ABAC &amp; Step-Up
            Auth
          </p>
        </div>
        <div>
          {user ? (
            <button type="button" onClick={handleLogout} className="btn-danger">
              Sign Out
            </button>
          ) : (
            <button
              type="button"
              onClick={() => handleGoogleLogin(false)}
              className="btn-google"
            >
              <svg width="16" height="16" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.65v3.03h3.88c2.27-2.09 3.66-5.17 3.66-9.12z"
                />
                <path
                  fill="#34A853"
                  d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.03c-1.07.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.26v3.13C3.27 21.36 7.34 24 12 24z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.28 14.29c-.25-.72-.38-1.49-.38-2.29s.13-1.57.38-2.29V6.57H1.26C.46 8.16 0 9.98 0 12s.46 3.84 1.26 5.43l4.02-3.14z"
                />
                <path
                  fill="#EA4335"
                  d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.34 0 3.27 2.64 1.26 6.57l4.02 3.14c.95-2.83 3.6-4.96 6.72-4.96z"
                />
              </svg>
              Sign In with Google
            </button>
          )}
        </div>
      </header>

      {/* Re-auth Warning Banner */}
      {reauthWarning && (
        <div className="alert-banner alert-warning">
          <div>
            <strong>⚠️ Step-Up Authentication Required:</strong>{" "}
            {reauthWarning.message} (Session is{" "}
            {reauthWarning.sessionAgeSeconds}s old; limit is{" "}
            {reauthWarning.maxAgeSeconds}s).
          </div>
          <button
            type="button"
            className="btn-warning"
            onClick={() => {
              if (user) {
                // If in dev mode, re-authenticate via dev login, otherwise trigger Google prompt=login
                handleDevLogin(user.role as any, user.email);
              } else {
                handleGoogleLogin(true);
              }
            }}
          >
            Re-authenticate Now
          </button>
        </div>
      )}

      <div className="dashboard-grid">
        {/* Left Column: Identity & Dev Controls */}
        <div className="card">
          <div className="card-title">
            <span>Identity &amp; Active Session</span>
            {user && (
              <span className={`badge badge-${user.role}`}>{user.role}</span>
            )}
          </div>

          {user ? (
            <div>
              <div className="profile-meta">
                <span className="meta-label">User:</span>
                <span className="meta-value">{user.name}</span>

                <span className="meta-label">Email:</span>
                <span className="meta-value">{user.email}</span>

                <span className="meta-label">Role:</span>
                <span className="meta-value">{user.role}</span>

                <span className="meta-label">User ID:</span>
                <span className="meta-value">{user.id}</span>

                <span className="meta-label">Session ID:</span>
                <span className="meta-value">{session?.id || "N/A"}</span>
              </div>
            </div>
          ) : (
            <p style={{ color: "var(--text-muted)" }}>
              No active session. Sign in with Google above, or use the dev login
              options below.
            </p>
          )}

          {/* Dev Login Fallback */}
          <div className="dev-controls">
            <span
              style={{
                fontSize: "12px",
                fontWeight: 600,
                color: "var(--text-muted)",
              }}
            >
              DEV LOGIN (OFFLINE / ROLE SWITCHER):
            </span>
            <div className="btn-group">
              <button
                type="button"
                onClick={() => handleDevLogin("admin")}
                className="btn-danger"
              >
                Login as Admin
              </button>
              <button
                type="button"
                onClick={() => handleDevLogin("manager")}
                className="btn-warning"
              >
                Login as Manager
              </button>
              <button
                type="button"
                onClick={() => handleDevLogin("user")}
                className="btn-primary"
              >
                Login as User
              </button>
            </div>

            <div className="input-row">
              <input
                type="text"
                placeholder="custom-user@university.edu"
                value={customEmail}
                onChange={(e) => setCustomEmail(e.target.value)}
              />
              <button
                type="button"
                onClick={() => handleDevLogin("user", customEmail)}
                disabled={!customEmail}
              >
                Login Custom
              </button>
            </div>
          </div>

          {/* Time-Travel / Freshness Demo Controls */}
          <div className="dev-controls" style={{ marginTop: "16px" }}>
            <span
              style={{
                fontSize: "12px",
                fontWeight: 600,
                color: "var(--text-muted)",
              }}
            >
              TIME-TRAVEL SIMULATOR (STEP-UP &amp; TIME WINDOWS):
            </span>
            <div className="btn-group">
              <button
                type="button"
                onClick={() => handleClockSetHour(14)}
                title="Set simulated time to 2:00 PM today (inside business hours)"
                className="btn-primary"
              >
                ☀️ Business Hours (2 PM)
              </button>
              <button
                type="button"
                onClick={() => handleClockSetHour(2)}
                title="Set simulated time to 2:00 AM tonight (outside business hours)"
                className="btn-danger"
              >
                🌙 After Hours (2 AM)
              </button>
              <button
                type="button"
                onClick={() => handleClockShift(305)}
                title="Advance clock by 5 minutes and 5 seconds to expire freshness"
              >
                ⏩ +5m 5s (Freshness)
              </button>
              <button
                type="button"
                onClick={handleClockReset}
                title="Reset simulated clock back to real system time"
              >
                🔄 Reset Clock
              </button>
            </div>

            {clockInfo && (
              <div
                style={{
                  marginTop: "10px",
                  fontSize: "12px",
                  background: "#090d16",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  border: "1px solid var(--border-color)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span>
                    <strong>Simulated Time:</strong>{" "}
                    {new Date(clockInfo.simulatedNow).toLocaleTimeString()} ({clockInfo.timezone})
                  </span>
                  {clockInfo.isOverridden && (
                    <span style={{ color: "var(--accent-amber)", fontWeight: 600 }}>
                      [SIMULATED]
                    </span>
                  )}
                </div>
                <div style={{ marginTop: "4px" }}>
                  <strong>Business Window:</strong>{" "}
                  <span
                    className={`badge ${
                      clockInfo.inBusinessHours ? "badge-fresh" : "badge-stale"
                    }`}
                  >
                    {clockInfo.inBusinessHours
                      ? "OPEN (08:00 - 18:00)"
                      : "CLOSED (AFTER HOURS)"}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Endpoint Test Bench */}
        <div className="card">
          <div className="card-title">Endpoint Test Bench</div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)", margin: "0 0 12px 0" }}>
            Test role gates, time windows, and step-up auth policies across endpoints:
          </p>

          <div className="btn-group">
            <button
              type="button"
              onClick={() => callApi("GET /api/me", "GET", "/api/me")}
            >
              GET /api/me
            </button>
            <button
              type="button"
              onClick={() =>
                callApi("GET /api/admin/users", "GET", "/api/admin/users")
              }
            >
              GET /api/admin/users
            </button>
            <button
              type="button"
              onClick={() => callApi("POST /api/export", "POST", "/api/export")}
              className="btn-warning"
            >
              POST /api/export (Fresh)
            </button>
          </div>

          <div className="input-row" style={{ marginTop: "12px" }}>
            <input
              type="text"
              placeholder="Target User ID for DELETE"
              value={targetUserId}
              onChange={(e) => setTargetUserId(e.target.value)}
            />
            <button
              type="button"
              className="btn-danger"
              onClick={() =>
                callApi(
                  `DELETE /api/users/${targetUserId}`,
                  "DELETE",
                  `/api/users/${targetUserId}`,
                )
              }
              disabled={!targetUserId}
            >
              DELETE User
            </button>
            {user && (
              <button
                type="button"
                onClick={() => setTargetUserId(user.id)}
                title="Fill own user ID to test anti-lockout protection"
              >
                Test Self-Delete Guard
              </button>
            )}
          </div>

          {/* Response Inspector */}
          <div style={{ marginTop: "16px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginBottom: "6px",
              }}
            >
              <span
                style={{
                  fontSize: "12px",
                  fontWeight: 600,
                  color: "var(--text-muted)",
                }}
              >
                LAST RESPONSE:
              </span>
              {lastResponse && (
                <span
                  className={`status-indicator ${
                    lastResponse.ok ? "success" : "error"
                  }`}
                >
                  HTTP {lastResponse.status} ({lastResponse.durationMs}ms)
                </span>
              )}
            </div>

            <pre className="json-display">
              {lastResponse
                ? JSON.stringify(lastResponse.data, null, 2)
                : '// Click any endpoint button above to inspect server response and HTTP status codes\n// Try POST /api/export after advancing the clock to see 403 REAUTH_REQUIRED'}
            </pre>
          </div>
        </div>
      </div>

      {/* Session Management Table */}
      <div className="card" style={{ marginBottom: "24px" }}>
        <div className="card-title">
          <span>Active Sessions ({sessionsList.length})</span>
          <div className="btn-group" style={{ margin: 0 }}>
            <button type="button" onClick={fetchSessions}>
              Refresh Sessions
            </button>
            <button
              type="button"
              className="btn-danger"
              onClick={() =>
                callApi(
                  "Revoke Other Sessions",
                  "POST",
                  "/api/sessions/revoke-others",
                )
              }
              disabled={sessionsList.length <= 1}
            >
              Revoke All Other Sessions
            </button>
          </div>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Device / IP</th>
                <th>Created</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {sessionsList.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                    No sessions found. Log in to establish a session.
                  </td>
                </tr>
              ) : (
                sessionsList.map((s) => (
                  <tr key={s.id}>
                    <td style={{ fontFamily: "var(--font-mono)" }}>
                      {s.id.slice(0, 16)}...
                    </td>
                    <td>
                      {s.ipAddress || "127.0.0.1"}
                      <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                        {s.userAgent?.slice(0, 45) || "Browser Session"}...
                      </div>
                    </td>
                    <td>{new Date(s.createdAt).toLocaleTimeString()}</td>
                    <td>
                      {s.isCurrent ? (
                        <span className="badge badge-fresh">Current Device</span>
                      ) : (
                        <span className="badge" style={{ background: "#334155" }}>
                          Remote
                        </span>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-danger"
                        style={{ padding: "4px 8px", fontSize: "12px" }}
                        onClick={() =>
                          callApi(
                            `Revoke Session ${s.id}`,
                            "DELETE",
                            `/api/sessions/${s.id}`,
                          )
                        }
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Log Table (Admin Only) */}
      {user?.role === "admin" && (
        <div className="card">
          <div className="card-title">
            <span>Security Audit Log (Latest 50 Events — Admin Only)</span>
            <button type="button" onClick={fetchAuditLogs}>
              Refresh Logs
            </button>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Decision</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                      No audit events recorded yet.
                    </td>
                  </tr>
                ) : (
                  auditLogs.map((log) => (
                    <tr key={log.id}>
                      <td style={{ whiteSpace: "nowrap", fontFamily: "var(--font-mono)", fontSize: "12px" }}>
                        {new Date(log.createdAt).toLocaleTimeString()}
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "12px" }}>
                        {log.userId ? log.userId.slice(0, 10) + "..." : "anonymous"}
                      </td>
                      <td style={{ fontWeight: 600 }}>{log.action}</td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "12px" }}>
                        {log.resource}
                      </td>
                      <td>
                        <span className={`badge badge-${log.decision}`}>
                          {log.decision}
                        </span>
                      </td>
                      <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                        {log.reason}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
