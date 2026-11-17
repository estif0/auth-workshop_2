// Express entry point.
//
// MIDDLEWARE ORDER — this matters enormously with Better Auth:
//   1. CORS           — sets headers before anything reads the body
//   2. Better Auth    — MUST come before express.json(); it reads the raw stream
//   3. express.json() — body parser; added here as a placeholder
//                       In Phase 3 we'll insert toNodeHandler(auth) at step 2
//   4. Routes
//
// Putting express.json() before Better Auth causes all /api/auth/* requests
// to hang silently — the stream is already consumed. This is the #1 gotcha.

import express from "express";
import cors from "cors";
import { sql } from "drizzle-orm";
import { env } from "./env.js";
import { db } from "./db/index.js";

const app = express();

// 1. CORS — allow the Vite dev server to send cookies
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true, // required for Set-Cookie to work cross-origin
  }),
);

// 2. Better Auth handler goes HERE in Phase 3 (before express.json)

// 3. Body parser
app.use(express.json());

// ── Health check ──────────────────────────────────────────────────────────────
// Verifies both the server is up AND the database connection works.
app.get("/api/health", async (_req, res) => {
  await db.execute(sql`SELECT 1`);
  res.json({ ok: true, env: env.NODE_ENV, ts: new Date().toISOString() });
});

app.listen(env.PORT, () => {
  console.log(`Server listening on http://localhost:${env.PORT}`);
  console.log(`  NODE_ENV: ${env.NODE_ENV}`);
  console.log(
    `  DB:       ${env.DATABASE_URL.replace(/:\/\/.*@/, "://<credentials>@")}`,
  );
});
