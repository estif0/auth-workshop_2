// Express entry point.
//
// ⚠️ CRITICAL MIDDLEWARE ORDER:
//   1. CORS           — sets Access-Control-* headers before request handling
//   2. Better Auth    — MUST be mounted BEFORE express.json(); Better Auth reads
//                       the raw stream for OAuth callbacks, body parsing, and webhooks.
//                       Mounting express.json() first causes auth requests to hang indefinitely.
//   3. express.json() — Parses JSON bodies for application routes.
//   4. Routes         — Application and dev routes.

import express from "express";
import cors from "cors";
import { sql } from "drizzle-orm";
import { toNodeHandler } from "better-auth/node";
import { env } from "./env.js";
import { db } from "./db/index.js";
import { auth } from "./auth.js";
import { devRouter } from "./routes/dev.js";

const app = express();

// 1. CORS — allow Vite frontend to communicate and set credentials (cookies)
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);

// 2. Better Auth handler — mounted BEFORE express.json()
app.all("/api/auth/*", toNodeHandler(auth));

// 3. Body parser for application endpoints
app.use(express.json());

// 4. Dev login fallback — physically absent when DEV_LOGIN_ENABLED != true
if (env.DEV_LOGIN_ENABLED) {
  app.use("/api/dev", devRouter);
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/api/health", async (_req, res) => {
  await db.execute(sql`SELECT 1`);
  res.json({ ok: true, env: env.NODE_ENV, ts: new Date().toISOString() });
});

app.listen(env.PORT, () => {
  console.log(`Server listening on http://localhost:${env.PORT}`);
  console.log(`  NODE_ENV:          ${env.NODE_ENV}`);
  console.log(`  DEV_LOGIN_ENABLED: ${env.DEV_LOGIN_ENABLED}`);
});
