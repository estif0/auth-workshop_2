import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Server } from "http";
import { app } from "../src/index.js";
import { db } from "../src/db/index.js";
import * as schema from "../src/db/schema.js";
import { can } from "../src/services/authz.js";
import { eq, desc } from "drizzle-orm";

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

// Helper: dev login to obtain a valid session cookie
async function loginAs(email: string, role: "admin" | "manager" | "user"): Promise<{ cookie: string; user: any }> {
  const res = await fetch(`${baseURL}/api/dev/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, role, name: `Test ${role}` }),
  });
  const cookie = res.headers.get("set-cookie")!.split(";")[0];
  const body = await res.json();
  return { cookie, user: body.user };
}

describe("Phase 5 - Central Authorization Engine (can) & Audit Logging", () => {
  describe("can() Policy Engine Unit Evaluation", () => {
    it("denies unauthenticated subject by default", async () => {
      const decision = await can(null, "read", "user:123");
      expect(decision.allow).toBe(false);
      expect(decision.reason).toContain("Unauthenticated");
    });

    it("denies unknown actions/resources by default (deny-by-default posture)", async () => {
      const subject = { id: "u-1", email: "user@test.com", role: "user" };
      const decision = await can(subject, "nuke", "database:main");
      expect(decision.allow).toBe(false);
      expect(decision.reason).toContain("Default deny");
    });

    it("allows admin to perform actions, but blocks self-deletion (anti-lockout guard)", async () => {
      const admin = { id: "admin-1", email: "admin@test.com", role: "admin" };

      // Admin deleting someone else -> allowed
      const allowDeleteOther = await can(admin, "delete", { type: "user", id: "other-user" });
      expect(allowDeleteOther.allow).toBe(true);

      // Admin deleting themselves -> denied!
      const denySelfDelete = await can(admin, "delete", { type: "user", id: "admin-1" });
      expect(denySelfDelete.allow).toBe(false);
      expect(denySelfDelete.reason).toContain("cannot delete their own account");
    });

    it("allows manager to export and view users, but denies user deletion", async () => {
      const manager = { id: "mgr-1", email: "mgr@test.com", role: "manager" };

      const allowExport = await can(manager, "export", { type: "export" });
      expect(allowExport.allow).toBe(true);

      const allowReadUser = await can(manager, "read", { type: "user", id: "any-user" });
      expect(allowReadUser.allow).toBe(true);

      const denyDeleteUser = await can(manager, "delete", { type: "user", id: "any-user" });
      expect(denyDeleteUser.allow).toBe(false);
      expect(denyDeleteUser.reason).toContain("not permitted to delete");
    });

    it("allows regular users to read/update only their own profile", async () => {
      const user = { id: "user-42", email: "user42@test.com", role: "user" };

      // Own profile
      const ownProfile = await can(user, "read", { type: "user", id: "user-42" });
      expect(ownProfile.allow).toBe(true);

      // Other profile -> denied
      const otherProfile = await can(user, "read", { type: "user", id: "user-99" });
      expect(otherProfile.allow).toBe(false);
    });

    it("persists an audit_logs row in the database for every decision", async () => {
      const actionTag = `test-audit-${Date.now()}`;
      await can(
        { id: "audit-user-1", email: "audit@test.com", role: "user" },
        actionTag,
        { type: "test-resource", id: "res-1" },
        { ip: "127.0.0.1", requestId: "req-audit-xyz" },
      );

      const [log] = await db
        .select()
        .from(schema.auditLogs)
        .where(eq(schema.auditLogs.action, actionTag));

      expect(log).toBeDefined();
      expect(log.userId).toBe("audit-user-1");
      expect(log.resource).toBe("test-resource:res-1");
      expect(log.decision).toBe("deny");
      expect(log.requestId).toBe("req-audit-xyz");
      expect(log.ip).toBe("127.0.0.1");
    });
  });

  describe("Sensitive Endpoints: DELETE /api/users/:id", () => {
    it("returns 401 when unauthenticated", async () => {
      const res = await fetch(`${baseURL}/api/users/some-id`, { method: "DELETE" });
      expect(res.status).toBe(401);
    });

    it("returns 403 when called by a regular user", async () => {
      const { cookie } = await loginAs(`user-${Date.now()}@example.com`, "user");
      const res = await fetch(`${baseURL}/api/users/some-id`, {
        method: "DELETE",
        headers: { cookie },
      });
      expect(res.status).toBe(403);
    });

    it("returns 403 when called by a manager", async () => {
      const { cookie } = await loginAs(`mgr-${Date.now()}@example.com`, "manager");
      const res = await fetch(`${baseURL}/api/users/some-id`, {
        method: "DELETE",
        headers: { cookie },
      });
      expect(res.status).toBe(403);
    });

    it("returns 403 when admin attempts to delete their own account (anti-lockout)", async () => {
      const { cookie, user: adminUser } = await loginAs(`admin-${Date.now()}@example.com`, "admin");
      const res = await fetch(`${baseURL}/api/users/${adminUser.id}`, {
        method: "DELETE",
        headers: { cookie },
      });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toContain("cannot delete their own account");
    });

    it("allows admin to delete another user and removes user from database", async () => {
      // 1. Create a target user to delete
      const { user: victimUser } = await loginAs(`victim-${Date.now()}@example.com`, "user");

      // 2. Admin logs in
      const { cookie } = await loginAs(`admin-${Date.now()}@example.com`, "admin");

      // 3. Admin deletes target user
      const res = await fetch(`${baseURL}/api/users/${victimUser.id}`, {
        method: "DELETE",
        headers: { cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(body.deletedUserId).toBe(victimUser.id);

      // 4. Verify user is gone from DB
      const [deletedRecord] = await db
        .select()
        .from(schema.user)
        .where(eq(schema.user.id, victimUser.id));
      expect(deletedRecord).toBeUndefined();
    });
  });

  describe("Sensitive Endpoints: POST /api/export", () => {
    it("returns 401 when unauthenticated", async () => {
      const res = await fetch(`${baseURL}/api/export`, { method: "POST" });
      expect(res.status).toBe(401);
    });

    it("returns 403 when called by a regular user", async () => {
      const { cookie } = await loginAs(`user-${Date.now()}@example.com`, "user");
      const res = await fetch(`${baseURL}/api/export`, {
        method: "POST",
        headers: { cookie },
      });
      expect(res.status).toBe(403);
    });

    it("allows manager to export data", async () => {
      const { cookie } = await loginAs(`mgr-${Date.now()}@example.com`, "manager");
      const res = await fetch(`${baseURL}/api/export`, {
        method: "POST",
        headers: { cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
      expect(Array.isArray(body.data)).toBe(true);
    });

    it("allows admin to export data", async () => {
      const { cookie } = await loginAs(`admin-${Date.now()}@example.com`, "admin");
      const res = await fetch(`${baseURL}/api/export`, {
        method: "POST",
        headers: { cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.success).toBe(true);
    });
  });

  describe("GET /api/admin/audit-logs", () => {
    it("returns 403 for non-admins", async () => {
      const { cookie } = await loginAs(`user-${Date.now()}@example.com`, "user");
      const res = await fetch(`${baseURL}/api/admin/audit-logs`, {
        headers: { cookie },
      });
      expect(res.status).toBe(403);
    });

    it("returns recent audit logs for admin", async () => {
      const { cookie } = await loginAs(`admin-${Date.now()}@example.com`, "admin");
      const res = await fetch(`${baseURL}/api/admin/audit-logs`, {
        headers: { cookie },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(Array.isArray(body.auditLogs)).toBe(true);
      expect(body.auditLogs.length).toBeGreaterThan(0);
    });
  });
});
