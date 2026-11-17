# Authentication in Depth: How Modern Login Works

> **Workshop Codebase for University Dev Club**  
> Focus: Production-grade session security, Google OIDC, role-based authorization (RBAC), context-aware authorization (ABAC), step-up re-authentication, session revocation, anti-IDOR protection, and structured audit logging.

---

## 🎯 What is this Workshop About?

Most developers know how to build a basic login form. But **logging in is only 10% of authentication**. What happens during the rest of that session's life?

- How do you verify permissions continuously on *every* request without trusting stale client tokens?
- How do you protect catastrophic operations (e.g. database exports or deleting user accounts) from stolen session cookies?
- How do you prevent users from maliciously revoking other users' sessions (IDOR vulnerabilities)?
- How do you enforce business-hour policies (ABAC) across Daylight Saving Time boundaries?
- How do you maintain an immutable security audit trail in PostgreSQL?

This repository is an educational, production-grade reference and hands-on workshop designed to answer those questions.

> 💡 **Scope Note:** This workshop deliberately uses **server-side sessions** stored in PostgreSQL and managed via [Better Auth](https://www.better-auth.com/). It intentionally does **not** cover JWTs or refresh tokens, which are taught in a separate dedicated project.

---

## 🏗️ Architecture & Stack

```
                        ┌────────────────────────────────────────────────────────┐
                        │              Browser (localhost:5173)                  │
                        │        React 19 + Plain CSS Test Dashboard             │
                        └──────────────────────────┬─────────────────────────────┘
                                                   │
                                                   │ /api/* (Proxied by Vite dev server)
                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Express Server (localhost:4000)                           │
│                                                                                        │
│  1. Request ID (AsyncLocalStorage context with X-Request-Id header)                    │
│  2. Pino Logger (redacts cookies, tokens, and authorization headers)                   │
│  3. CORS & Stricter Auth Rate Limiter (20 req / 15m)                                   │
│  4. Better Auth Handler (mounted BEFORE express.json() to prevent stream consumption)  │
│  5. express.json() Body Parser                                                         │
│  6. General API Rate Limiter (100 req / 15m)                                           │
│  7. Protected Application Routes:                                                      │
│     - authenticate (verifies HMAC-signed session cookie against DB)                    │
│     - requireRole (fast 401 vs. 403 role-based gatekeeper)                             │
│     - requireFreshAuth (step-up: session < 5 min old, returns 403 REAUTH_REQUIRED)     │
│     - can() Policy Engine (deny-by-default ABAC + anti-lockout + time windows)         │
│     - logAuditEvent() (writes security events to Pino + PostgreSQL audit_logs table)   │
└──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                           │
                                           │ SQL Queries & Migrations (Drizzle ORM)
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                         PostgreSQL in Docker (localhost:5432)                          │
│  - user (id, name, email, role, email_verified, ...)                                   │
│  - session (id, token, user_id, expires_at, created_at, ip_address, user_agent, ...)   │
│  - account (id, user_id, provider_id, access_token, ...)                               │
│  - audit_logs (id, request_id, user_id, action, resource, decision, reason, ip, ...)   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

- **Backend:** Node.js, Express v4, TypeScript (strict ESM).
- **Authentication:** Better Auth v1.7.25 with Google Social Provider + Dev fallback login.
- **Database:** PostgreSQL 17 (Docker) with Drizzle ORM and Drizzle Kit.
- **Frontend:** React 19, Vite, TypeScript, and clean, high-contrast Plain CSS (zero UI library bloat, projector-optimized).
- **Security & Observability:** Pino logging with credential redaction, AsyncLocalStorage request IDs, express-rate-limit, and strict zero-trust `can()` authorization.
- **Testing:** Vitest with injectable clocks (`Clock = () => number`) for deterministic time testing.

---

## 🌿 Branches: `main` vs. `solution`

This repository has two branches:

1. **`main` (The Workshop Starting Point):**
   - Contains the full foundation (database schema, Better Auth, Express middleware pipeline, test dashboard).
   - Contains exactly **3 hands-on workshop tasks** stubbed with `// TODO(workshop)` comments.
   - Foundation tests pass; workshop task tests fail with descriptive error messages guiding your implementation.
2. **`solution` (The Reference Implementation):**
   - Contains the complete, working, production-grade solution for all 3 tasks.
   - All 49 automated tests pass.

---

## ⚡ Quickstart

### 1. Prerequisites
- [Node.js](https://nodejs.org/) v18+ (v20+ recommended)
- [Docker & Docker Compose](https://www.docker.com/)

### 2. Clone & Install
```bash
git clone <repo-url> auth-workshop
cd auth-workshop

# Install dependencies in both workspaces
npm install --prefix server
npm install --prefix web
```

### 3. Environment Setup
Copy the committed `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(The default `.env` is already configured for Docker PostgreSQL on port 5432 and backend on port 4000. Google OAuth credentials are optional; you can use the built-in Dev Login without any internet access!)*

### 4. Start PostgreSQL & Run Migrations
```bash
# Start PostgreSQL in background
npm run docker:up

# Run database migrations
npm run db:migrate --prefix server
```

### 5. Start the Application
Open two terminal windows:

```bash
# Terminal 1: Express Server (port 4000)
npm run server

# Terminal 2: Vite React Frontend (port 5173)
npm run web
```

Open your browser at **[http://localhost:5173](http://localhost:5173)** to open the interactive test dashboard!

---

## 🛠️ The 3 Workshop Tasks (on `main`)

When you are on the `main` branch, three critical security features are left for you to implement:

### Task 1: Time-Window Policy Rule (ABAC)
- **Goal:** Implement an Attribute-Based Access Control rule inside `can()` that restricts sensitive operations (`"delete"` and `"export"`) to official business hours: **08:00 to 18:00, Monday through Friday**, in a configurable timezone (e.g. `"America/New_York"`), while accurately handling Daylight Saving Time (DST) transitions.
- **File:** `server/src/services/authz.ts`
- **Hint Guide:** [`workshop/task1-time-window.md`](workshop/task1-time-window.md)
- **Test Command:**
  ```bash
  npx vitest run test/task1-time-window.test.ts --dir server
  ```

### Task 2: Step-Up Authentication Middleware (`requireFreshAuth`)
- **Goal:** Protect sensitive endpoints (`DELETE /api/users/:id` and `POST /api/export`) by requiring proof of recent authentication. If the session was created more than **5 minutes (300 seconds)** ago, reject the request with HTTP 403, code `REAUTH_REQUIRED`, and record a security audit event.
- **File:** `server/src/middleware/requireFreshAuth.ts`
- **Hint Guide:** [`workshop/task2-fresh-auth.md`](workshop/task2-fresh-auth.md)
- **Test Command:**
  ```bash
  npx vitest run test/step-up.test.ts --dir server
  ```

### Task 3: Session Revocation & Anti-IDOR Ownership Check
- **Goal:** Implement `DELETE /api/sessions/:id` and `POST /api/sessions/revoke-others`. Prevent Insecure Direct Object Reference (IDOR) attacks: User A must never be able to revoke a session belonging to User B. Clear the browser cookie if the user revokes their current active session, and write structured audit records.
- **File:** `server/src/routes/sessions.ts`
- **Hint Guide:** [`workshop/task3-session-revoke.md`](workshop/task3-session-revoke.md)
- **Test Command:**
  ```bash
  npx vitest run test/sessions.test.ts --dir server
  ```

---

## 🧪 Running Tests

The test harness uses **Vitest** and includes injectable clocks (`Clock = () => number`) to test time boundaries deterministically without sleeping:

```bash
# Run all type checks and test suites across the project
npm run check

# Or run tests directly in the server directory
npm run test --prefix server
```

---

## 🖥️ Interactive Test Dashboard Features (`http://localhost:5173`)

The frontend is a lightweight test dashboard built specifically for exploring and demoing auth concepts:

1. **Google OIDC Login & Dev Fallback:**
   - Sign in with real Google OAuth (if client credentials are provided in `.env`).
   - One-click **Dev Login toolbar** to instantly switch between `Admin`, `Manager`, and `User` roles without internet connectivity.
2. **Interactive Endpoint Test Bench:**
   - Trigger `GET /api/me`, `GET /api/admin/users`, `POST /api/export`, and `DELETE /api/users/:id`.
   - Inspect status codes, response times in ms, and formatted JSON output.
3. **Step-Up Warning & Dynamic Re-Auth:**
   - When a sensitive endpoint returns `403 REAUTH_REQUIRED`, a warning banner alerts the user with a 1-click **"Re-authenticate Now"** button.
4. **Time-Travel Simulator (Dev Mode):**
   - Click `☀️ Business Hours (2 PM)` to set simulated time to 2:00 PM today (inside business hours).
   - Click `🌙 After Hours (2 AM)` or `⏩ +9h` to jump outside business hours (to test ABAC time-window rejection).
   - Click `⏩ +5m 5s (Freshness)` to advance the server's simulated clock past the 5-minute freshness window.
   - Click `🔄 Reset Clock` to restore real system time.
   - Live banner displays the active simulated time, detected timezone, and an `OPEN (08:00 - 18:00)` vs `CLOSED (AFTER HOURS)` status badge.
5. **Session Management Table:**
   - View all active sessions, IP addresses, user agents, and a `Current Device` badge.
   - Revoke individual remote sessions, or click **"Revoke All Other Sessions"**.
6. **Live Security Audit Log (Admin Only):**
   - Inspect every authorization decision (both `ALLOW` in green and `DENY` in red) with request IDs, timestamps, and policy reasons.

---

## 📁 Repository Directory Structure

```text
auth-workshop/
├── docker-compose.yml              # PostgreSQL 17-alpine on port 5432
├── .env.example                    # Sample environment variables (committed)
├── package.json                    # Root scripts: server, web, check, docker:*
│
├── workshop/                       # Student exercise hints & instructions
│   ├── task1-time-window.md        # Task 1: Time-Window ABAC Policy Guide
│   ├── task2-fresh-auth.md         # Task 2: Step-Up Authentication Guide
│   └── task3-session-revoke.md     # Task 3: Session Revocation & IDOR Guide
│
├── server/                         # Express Backend (ESM, strict TypeScript)
│   ├── src/
│   │   ├── auth.ts                 # Better Auth Google provider & hooks
│   │   ├── env.ts                  # Zod environment schema validation
│   │   ├── index.ts                # Express pipeline & route registration
│   │   ├── db/
│   │   │   ├── index.ts            # Drizzle database client
│   │   │   ├── auth-schema.ts      # Better Auth generated schema
│   │   │   └── schema.ts           # audit_logs table definition
│   │   ├── lib/
│   │   │   └── clock.ts            # Injectable clock for testable time
│   │   ├── middleware/
│   │   │   ├── requestId.ts        # AsyncLocalStorage request tracer
│   │   │   ├── logger.ts           # Pino HTTP logger with redaction
│   │   │   ├── authenticate.ts     # Session cookie verification
│   │   │   ├── requireRole.ts      # 401 vs 403 role gatekeeper
│   │   │   ├── requireFreshAuth.ts # Task 2 stub (main) / solution
│   │   │   └── rateLimit.ts        # Auth and general rate limits
│   │   ├── routes/
│   │   │   ├── dev.ts              # Dev login & time-travel clock endpoint
│   │   │   ├── me.ts               # GET /api/me
│   │   │   ├── admin.ts            # GET /api/admin/users & /api/admin/audit-logs
│   │   │   ├── users.ts            # DELETE /api/users/:id
│   │   │   ├── export.ts           # POST /api/export
│   │   │   └── sessions.ts         # Task 3 stub (main) / solution
│   │   └── services/
│   │       ├── audit.ts            # PostgreSQL & Pino structured audit service
│   │       └── authz.ts            # Task 1 stub (main) / solution
│   └── test/                       # 7 Vitest test suites (49 tests)
│
└── web/                            # Minimal React + Vite Frontend (Plain CSS)
    ├── vite.config.ts              # Reverse proxy forwarding /api to port 4000
    └── src/
        ├── App.tsx                 # Interactive test bench, sessions, audit viewer
        └── App.css                 # Clean, high-contrast, projector-ready styles
```

---

## 📜 Useful Commands Reference

| Command | Description |
|---|---|
| `npm run check` | Runs full TypeScript compilation check and all Vitest test suites |
| `npm run server` | Starts Express server in development mode (`tsx watch`) on port 4000 |
| `npm run web` | Starts Vite React frontend on port 5173 |
| `npm run docker:up` | Boots PostgreSQL 17 in background |
| `npm run docker:down` | Stops PostgreSQL container |
| `npm run docker:logs` | Follows PostgreSQL logs |
| `npm run db:migrate --prefix server` | Runs Drizzle migrations against PostgreSQL |
| `npm run db:studio --prefix server` | Opens Drizzle Studio GUI for inspecting database rows |
| `git checkout solution` | Switches to the complete working reference solution |
| `git checkout main` | Switches back to the workshop exercise starting point |
