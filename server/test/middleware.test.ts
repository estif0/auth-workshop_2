import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Server } from "http";
import { makeSignature } from "better-auth/crypto";
import { app } from "../src/index.js";
import { auth } from "../src/auth.js";
import { db } from "../src/db/index.js";
import * as schema from "../src/db/schema.js";
import { eq } from "drizzle-orm";

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

describe("Phase 4 - Core Middleware & Protected Routes", () => {
  it("requestIdMiddleware assigns and propagates X-Request-Id header", async () => {
    // 1. Without incoming header -> generates one
    const res1 = await fetch(`${baseURL}/api/health`);
    const reqId1 = res1.headers.get("x-request-id");
    expect(reqId1).toBeDefined();
    expect(reqId1!.length).toBeGreaterThan(10);

    // 2. With incoming header -> propagates it
    const customId = "custom-test-trace-id-12345";
    const res2 = await fetch(`${baseURL}/api/health`, {
      headers: { "x-request-id": customId },
    });
    expect(res2.headers.get("x-request-id")).toBe(customId);
  });

  it("GET /api/me returns 401 when unauthenticated", async () => {
    const res = await fetch(`${baseURL}/api/me`);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.code).toBe("UNAUTHORIZED");
  });

  it("GET /api/admin/users returns 401 when unauthenticated", async () => {
    const res = await fetch(`${baseURL}/api/admin/users`);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.code).toBe("UNAUTHORIZED");
  });

  it("GET /api/admin/users returns 403 when authenticated as a regular user", async () => {
    // 1. Login as regular user via dev login
    const userEmail = `regular-${Date.now()}@example.com`;
    const loginRes = await fetch(`${baseURL}/api/dev/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: userEmail, role: "user" }),
    });
    const cookie = loginRes.headers.get("set-cookie")!.split(";")[0];

    // 2. Access /api/me -> 200 OK
    const meRes = await fetch(`${baseURL}/api/me`, {
      headers: { cookie },
    });
    expect(meRes.status).toBe(200);
    const meData = await meRes.json();
    expect(meData.user.email).toBe(userEmail);
    expect(meData.user.role).toBe("user");

    // 3. Access /api/admin/users -> 403 Forbidden (401 vs 403 done correctly!)
    const adminRes = await fetch(`${baseURL}/api/admin/users`, {
      headers: { cookie },
    });
    expect(adminRes.status).toBe(403);
    const adminBody = await adminRes.json();
    expect(adminBody.code).toBe("FORBIDDEN");
    expect(adminBody.currentRole).toBe("user");
    expect(adminBody.requiredRoles).toContain("admin");

    // Cleanup
    await db.delete(schema.user).where(eq(schema.user.email, userEmail));
  });

  it("GET /api/admin/users returns 200 when authenticated as an admin", async () => {
    // 1. Login as admin user via dev login
    const adminEmail = `admin-${Date.now()}@university.edu`;
    const loginRes = await fetch(`${baseURL}/api/dev/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: adminEmail, role: "admin" }),
    });
    const cookie = loginRes.headers.get("set-cookie")!.split(";")[0];

    // 2. Access /api/admin/users -> 200 OK with user list
    const adminRes = await fetch(`${baseURL}/api/admin/users`, {
      headers: { cookie },
    });
    expect(adminRes.status).toBe(200);
    const body = await adminRes.json();
    expect(Array.isArray(body.users)).toBe(true);
    expect(body.users.some((u: any) => u.email === adminEmail)).toBe(true);

    // Cleanup
    await db.delete(schema.user).where(eq(schema.user.email, adminEmail));
  });
});
