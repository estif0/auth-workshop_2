// Express entry point.
//
// ⚠️ MIDDLEWARE PIPELINE ORDER:
//   1. Request ID (AsyncLocalStorage) — attaches X-Request-Id and creates async context.
//   2. HTTP Access Logger (Pino)      — logs request method, URL, status code, duration, user.
//   3. CORS                           — handles preflights and enables credentials.
//   4. Auth Rate Limiter              — protects sensitive auth routes from brute-force.
//   5. Better Auth handler            — MUST be mounted BEFORE express.json() to avoid
//                                       stream-draining deadlocks.
//   6. express.json()                 — parses JSON bodies for downstream application routes.
//   7. General API Rate Limiter       — protects standard API routes.
//   8. Application Routes             — /api/me, /api/admin, /api/dev, /api/health.

import express from "express";
import cors from "cors";
import { sql } from "drizzle-orm";
import { toNodeHandler } from "better-auth/node";
import { env } from "./env.js";
import { db } from "./db/index.js";
import { auth } from "./auth.js";
import { requestIdMiddleware } from "./middleware/requestId.js";
import { httpLogger } from "./middleware/logger.js";
import { authLimiter, generalLimiter } from "./middleware/rateLimit.js";
import { devRouter } from "./routes/dev.js";
import { meRouter } from "./routes/me.js";
import { adminRouter } from "./routes/admin.js";

const app = express();

// 1. Request ID context via AsyncLocalStorage
app.use(requestIdMiddleware);

// 2. HTTP logger
app.use(httpLogger);

// 3. CORS
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);

// 4. Stricter rate limiter for authentication routes
app.use("/api/auth", authLimiter);
app.use("/api/dev", authLimiter);

// 5. Better Auth handler — mounted BEFORE express.json()
app.all("/api/auth/*", toNodeHandler(auth));

// 6. Body parser for application endpoints
app.use(express.json());

// 7. General API rate limiter
app.use("/api", generalLimiter);

// 8. Application routes
if (
  env.DEV_LOGIN_ENABLED ||
  process.env.DEV_LOGIN_ENABLED === "true" ||
  env.NODE_ENV === "test"
) {
  app.use("/api/dev", devRouter);
}
app.use("/api", meRouter);
app.use("/api/admin", adminRouter);

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/api/health", async (_req, res) => {
  await db.execute(sql`SELECT 1`);
  res.json({ ok: true, env: env.NODE_ENV, ts: new Date().toISOString() });
});

// Start listening only when executed directly, not during test imports
if (process.env.NODE_ENV !== "test") {
  app.listen(env.PORT, () => {
    console.log(`Server listening on http://localhost:${env.PORT}`);
    console.log(`  NODE_ENV:          ${env.NODE_ENV}`);
    console.log(`  DEV_LOGIN_ENABLED: ${env.DEV_LOGIN_ENABLED}`);
  });
}

export { app };
