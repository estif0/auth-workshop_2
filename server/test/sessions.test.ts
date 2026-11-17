import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Server } from "http";
import { app } from "../src/index.js";
import { db } from "../src/db/index.js";
import * as schema from "../src/db/schema.js";
import { and, eq } from "drizzle-orm";

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

async function loginAs(email: string, role: "admin" | "manager" | "user" = "user") {
  const res = await fetch(`${baseURL}/api/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, role, name: `User ${email.split("@")[0]}` }),
  });
  const cookie = res.headers.get("set-cookie")!.split(";")[0];
  const body = await res.json();
  return { cookie, user: body.user, session: body.session };
}

describe("Phase 7 - Session Management & IDOR Revocation Prevention", () => {
  describe("GET /api/sessions", () => {
    it("returns 401 when unauthenticated", async () => {
      const res = await fetch(`${baseURL}/api/sessions`);
      expect(res.status).toBe(401);
    });

    it("lists active sessions and correctly marks current session", async () => {
      const email = `multi-session-${Date.now()}@example.com`;

      // Session 1 (e.g. Desktop browser)
      const s1 = await loginAs(email, "user");

      // Session 2 (e.g. Mobile browser)
      const s2 = await loginAs(email, "user");

      // Query from Session 1
      const res1 = await fetch(`${baseURL}/api/sessions`, {
        headers: { cookie: s1.cookie },
      });
      expect(res1.status).toBe(200);
      const data1 = await res1.json();
      expect(Array.isArray(data1.sessions)).toBe(true);
      expect(data1.sessions.length).toBeGreaterThanOrEqual(2);

      const currentFromS1 = data1.sessions.find((s: any) => s.id === s1.session.id);
      const otherFromS1 = data1.sessions.find((s: any) => s.id === s2.session.id);
      expect(currentFromS1.isCurrent).toBe(true);
      expect(otherFromS1.isCurrent).toBe(false);

      // Query from Session 2
      const res2 = await fetch(`${baseURL}/api/sessions`, {
        headers: { cookie: s2.cookie },
      });
      const data2 = await res2.json();
      const currentFromS2 = data2.sessions.find((s: any) => s.id === s2.session.id);
      const otherFromS2 = data2.sessions.find((s: any) => s.id === s1.session.id);
      expect(currentFromS2.isCurrent).toBe(true);
      expect(otherFromS2.isCurrent).toBe(false);
    });
  });

  describe("DELETE /api/sessions/:id (Anti-IDOR Ownership)", () => {
    it("returns 401 when unauthenticated", async () => {
      const res = await fetch(`${baseURL}/api/sessions/some-id`, { method: "DELETE" });
      expect(res.status).toBe(401);
    });

    it("returns 404 for nonexistent session", async () => {
      const { cookie } = await loginAs(`alice-${Date.now()}@example.com`, "user");
      const res = await fetch(`${baseURL}/api/sessions/nonexistent-session-id`, {
        method: "DELETE",
        headers: { cookie },
      });
      expect(res.status).toBe(404);
      expect((await res.json()).code).toBe("NOT_FOUND");
    });

    it("CRITICAL: blocks IDOR attack when User A attempts to revoke User B's session", async () => {
      // User A (attacker)
      const userA = await loginAs(`attacker-${Date.now()}@example.com`, "user");

      // User B (victim)
      const userB = await loginAs(`victim-${Date.now()}@example.com`, "user");

      // Attacker attempts to delete victim's session
      const res = await fetch(`${baseURL}/api/sessions/${userB.session.id}`, {
        method: "DELETE",
        headers: { cookie: userA.cookie },
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.code).toBe("FORBIDDEN");
      expect(body.error).toContain("another user");

      // 1. Verify victim's session is STILL active in the database
      const [victimDbSession] = await db
        .select()
        .from(schema.session)
        .where(eq(schema.session.id, userB.session.id));
      expect(victimDbSession).toBeDefined();

      // 2. Verify an IDOR prevention audit log was written
      const [auditLog] = await db
        .select()
        .from(schema.auditLogs)
        .where(
          and(
            eq(schema.auditLogs.action, "session_revoke_denied"),
            eq(schema.auditLogs.userId, userA.user.id),
          ),
        );
      expect(auditLog).toBeDefined();
      expect(auditLog.decision).toBe("deny");
      expect(auditLog.reason).toContain("IDOR prevention");
    });

    it("allows a user to revoke their own secondary session", async () => {
      const email = `self-revoke-${Date.now()}@example.com`;
      const s1 = await loginAs(email, "user");
      const s2 = await loginAs(email, "user");

      // User from s1 revokes s2
      const res = await fetch(`${baseURL}/api/sessions/${s2.session.id}`, {
        method: "DELETE",
        headers: { cookie: s1.cookie },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.revokedSessionId).toBe(s2.session.id);
      expect(body.wasCurrentSession).toBe(false);

      // Verify s2 is gone from DB
      const [deletedSession] = await db
        .select()
        .from(schema.session)
        .where(eq(schema.session.id, s2.session.id));
      expect(deletedSession).toBeUndefined();

      // Verify s1 is still active
      const meRes = await fetch(`${baseURL}/api/me`, {
        headers: { cookie: s1.cookie },
      });
      expect(meRes.status).toBe(200);
    });

    it("clears session cookie when user revokes their own current session", async () => {
      const email = `logout-self-${Date.now()}@example.com`;
      const s = await loginAs(email, "user");

      const res = await fetch(`${baseURL}/api/sessions/${s.session.id}`, {
        method: "DELETE",
        headers: { cookie: s.cookie },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.wasCurrentSession).toBe(true);

      // Subsequent access with this session cookie returns 401
      const meRes = await fetch(`${baseURL}/api/me`, {
        headers: { cookie: s.cookie },
      });
      expect(meRes.status).toBe(401);
    });
  });

  describe("POST /api/sessions/revoke-others", () => {
    it("revokes all other sessions except the current one", async () => {
      const email = `revoke-others-${Date.now()}@example.com`;
      const s1 = await loginAs(email, "user");
      const s2 = await loginAs(email, "user");
      const s3 = await loginAs(email, "user");

      // From s3, revoke s1 and s2
      const res = await fetch(`${baseURL}/api/sessions/revoke-others`, {
        method: "POST",
        headers: { cookie: s3.cookie },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.revokedCount).toBeGreaterThanOrEqual(2);

      // s1 and s2 should now be 401
      const me1 = await fetch(`${baseURL}/api/me`, { headers: { cookie: s1.cookie } });
      const me2 = await fetch(`${baseURL}/api/me`, { headers: { cookie: s2.cookie } });
      expect(me1.status).toBe(401);
      expect(me2.status).toBe(401);

      // s3 is still active
      const me3 = await fetch(`${baseURL}/api/me`, { headers: { cookie: s3.cookie } });
      expect(me3.status).toBe(200);

      // Verify audit log
      const [auditLog] = await db
        .select()
        .from(schema.auditLogs)
        .where(
          and(
            eq(schema.auditLogs.action, "session_revoke_others"),
            eq(schema.auditLogs.userId, s3.user.id),
          ),
        );
      expect(auditLog).toBeDefined();
      expect(auditLog.decision).toBe("allow");
    });
  });
});
