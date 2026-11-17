import { describe, it, expect } from "vitest";
import express from "express";
import cors from "cors";
import { toNodeHandler } from "better-auth/node";
import { auth } from "../src/auth.js";
import { devRouter } from "../src/routes/dev.js";
import { db } from "../src/db/index.js";
import * as schema from "../src/db/schema.js";
import { eq } from "drizzle-orm";

// Construct test express app mirroring src/index.ts
const app = express();
app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.all("/api/auth/*", toNodeHandler(auth));
app.use(express.json());
app.use("/api/dev", devRouter);

describe("Dev Fallback Login Route (/api/dev/login)", () => {
  it("creates a user and sets signed session cookie", async () => {
    const server = app.listen(0);
    const address = server.address() as { port: number };
    const baseURL = `http://localhost:${address.port}`;

    try {
      const email = `dev-${Date.now()}@devclub.org`;
      const res = await fetch(`${baseURL}/api/dev/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, name: "Dev Tester", role: "manager" }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.success).toBe(true);
      expect(data.user.email).toBe(email);
      expect(data.user.role).toBe("manager");

      // Verify Set-Cookie header contains auth-workshop.session_token
      const setCookie = res.headers.get("set-cookie");
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain("auth-workshop.session_token=");
      expect(setCookie).toContain("HttpOnly");
      expect(setCookie).toContain("SameSite=Lax");

      // Now use that cookie to hit Better Auth's /api/auth/get-session
      const sessionRes = await fetch(`${baseURL}/api/auth/get-session`, {
        headers: {
          cookie: setCookie!.split(";")[0],
        },
      });

      expect(sessionRes.status).toBe(200);
      const sessionData = await sessionRes.json();
      expect(sessionData).not.toBeNull();
      expect(sessionData.user.email).toBe(email);
      expect(sessionData.user.role).toBe("manager");

      // Cleanup
      await db.delete(schema.user).where(eq(schema.user.email, email));
    } finally {
      server.close();
    }
  });
});
