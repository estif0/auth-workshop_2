import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import type { Server } from "http";
import { app } from "../src/index.js";
import { db } from "../src/db/index.js";
import * as schema from "../src/db/schema.js";
import { and, eq } from "drizzle-orm";
import { createRequireFreshAuth } from "../src/middleware/requireFreshAuth.js";

let server: Server;
let baseURL: string;

beforeAll(async () => {
  server = app.listen(0);
  const address = server.address() as { port: number };
  baseURL = `http://localhost:${address.port}`;
});

afterAll(() => {
  server.close();
});

beforeEach(async () => {
  // Reset clock override before each test
  await fetch(`${baseURL}/api/dev/clock`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reset: true }),
  });
});

async function loginAs(email: string, role: "admin" | "manager" | "user") {
  const res = await fetch(`${baseURL}/api/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, role, name: `Test ${role}` }),
  });
  const cookie = res.headers.get("set-cookie")!.split(";")[0];
  const body = await res.json();
  return { cookie, user: body.user, session: body.session };
}

describe("Phase 6 - Step-Up Authentication (requireFreshAuth)", () => {
  describe("Unit & Injected Clock Freshness Enforcement", () => {
    it("createRequireFreshAuth allows request when session is within threshold", async () => {
      const baseTime = 1_700_000_000_000;
      let mockTime = baseTime;
      const clock = () => mockTime;

      const middleware = createRequireFreshAuth(300, clock);

      const req: any = {
        session: { createdAt: new Date(baseTime) },
        user: { id: "test-user-fresh" },
        originalUrl: "/api/export",
        ip: "127.0.0.1",
        id: "req-1",
      };
      const res: any = {
        status: (code: number) => {
          res.statusCode = code;
          return res;
        },
        json: (data: any) => {
          res.body = data;
        },
      };

      let nextCalled = false;
      const next = () => {
        nextCalled = true;
      };

      // 1. Session is 60 seconds old -> allowed
      mockTime = baseTime + 60 * 1000;
      await middleware(req, res, next);
      expect(nextCalled).toBe(true);

      // 2. Session is 301 seconds old -> blocked with REAUTH_REQUIRED
      nextCalled = false;
      mockTime = baseTime + 301 * 1000;
      await middleware(req, res, next);
      expect(nextCalled).toBe(false);
      expect(res.statusCode).toBe(403);
      expect(res.body.code).toBe("REAUTH_REQUIRED");
      expect(res.body.sessionAgeSeconds).toBe(301);
    });

    it("writes an audit log record when re-authentication is required", async () => {
      const baseTime = 1_700_000_000_000;
      const clock = () => baseTime + 400 * 1000; // 400 seconds old (> 300)

      const middleware = createRequireFreshAuth(300, clock);

      const req: any = {
        session: { createdAt: new Date(baseTime) },
        user: { id: "user-audit-freshness" },
        originalUrl: "/api/export",
        ip: "127.0.0.1",
        id: "req-fresh-audit",
      };
      const res: any = {
        status: (code: number) => {
          res.statusCode = code;
          return res;
        },
        json: (data: any) => {
          res.body = data;
        },
      };

      await middleware(req, res, () => {});
      expect(res.statusCode).toBe(403);

      const [log] = await db
        .select()
        .from(schema.auditLogs)
        .where(
          and(
            eq(schema.auditLogs.action, "step_up_auth_required"),
            eq(schema.auditLogs.userId, "user-audit-freshness"),
          ),
        );

      expect(log).toBeDefined();
      expect(log.userId).toBe("user-audit-freshness");
      expect(log.decision).toBe("deny");
      expect(log.reason).toContain("exceeds freshness threshold");
    });
  });

  describe("Sensitive Endpoints Freshness Integration", () => {
    it("allows POST /api/export immediately after login (< 5 min old)", async () => {
      const { cookie } = await loginAs(`manager-${Date.now()}@example.com`, "manager");

      const res = await fetch(`${baseURL}/api/export`, {
        method: "POST",
        headers: { cookie },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
    });

    it("returns 403 REAUTH_REQUIRED when session is older than 5 minutes", async () => {
      const email = `manager-stale-${Date.now()}@example.com`;
      const { cookie } = await loginAs(email, "manager");

      // Advance simulated clock by 305 seconds (5 minutes and 5 seconds)
      const clockRes = await fetch(`${baseURL}/api/dev/clock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ offsetSeconds: 305 }),
      });
      expect(clockRes.status).toBe(200);

      // Now attempt sensitive export endpoint
      const res = await fetch(`${baseURL}/api/export`, {
        method: "POST",
        headers: { cookie },
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.code).toBe("REAUTH_REQUIRED");
      expect(body.maxAgeSeconds).toBe(300);
      expect(body.sessionAgeSeconds).toBeGreaterThanOrEqual(300);
    });

    it("succeeds after re-authenticating (step-up flow)", async () => {
      const email = `admin-stepup-${Date.now()}@example.com`;
      let { cookie } = await loginAs(email, "admin");

      // Advance clock past 5 minutes
      await fetch(`${baseURL}/api/dev/clock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ offsetSeconds: 350 }),
      });

      // Verify blocked with REAUTH_REQUIRED
      const blockedRes = await fetch(`${baseURL}/api/export`, {
        method: "POST",
        headers: { cookie },
      });
      expect(blockedRes.status).toBe(403);
      expect((await blockedRes.json()).code).toBe("REAUTH_REQUIRED");

      // Re-authenticate: simulate step-up re-login (Google/Dev login sets fresh session)
      const reAuthRes = await loginAs(email, "admin");
      cookie = reAuthRes.cookie;

      // Sensitive action now succeeds with fresh session!
      const successRes = await fetch(`${baseURL}/api/export`, {
        method: "POST",
        headers: { cookie },
      });
      expect(successRes.status).toBe(200);
      expect((await successRes.json()).success).toBe(true);
    });
  });
});
