import { describe, it, expect } from "vitest";
import { makeSignature } from "better-auth/crypto";
import { auth, getAdminEmails } from "../src/auth.js";
import { db } from "../src/db/index.js";
import * as schema from "../src/db/schema.js";
import { eq } from "drizzle-orm";

describe("Phase 3 - Auth Configuration & Session Lifecycle", () => {
  it("correctly identifies admin emails from env", () => {
    process.env.ADMIN_EMAILS = "instructor@university.edu,admin@club.dev";
    const emails = getAdminEmails();
    expect(emails).toContain("instructor@university.edu");
    expect(emails).toContain("admin@club.dev");
  });

  it("creates a session and validates it via Better Auth getSession", async () => {
    const testEmail = `test-${Date.now()}@example.com`;

    // 1. Create a user
    const ctx = await auth.$context;
    const user = await ctx.internalAdapter.createUser({
      name: "Test User",
      email: testEmail,
      emailVerified: true,
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    expect(user).toBeDefined();
    expect(user.role).toBe("user");

    // 2. Create a session for this user
    const session = await ctx.internalAdapter.createSession(user.id);
    expect(session).toBeDefined();
    expect(session.token).toBeDefined();
    expect(session.userId).toBe(user.id);

    // 3. Generate HMAC signature for the session cookie
    const cookieName = ctx.authCookies.sessionToken.name;
    const signature = await makeSignature(session.token, ctx.secret);
    const headers = new Headers({
      cookie: `${cookieName}=${session.token}.${signature}`,
    });

    // 4. Verify Better Auth getSession retrieves this session via headers
    const sessionData = await auth.api.getSession({
      headers,
    });

    expect(sessionData).toBeDefined();
    expect(sessionData?.user.email).toBe(testEmail);
    expect(sessionData?.user.role).toBe("user");
    expect(sessionData?.session.token).toBe(session.token);

    // Cleanup
    await db.delete(schema.user).where(eq(schema.user.id, user.id));
  });

  it("applies admin role for emails matching ADMIN_EMAILS via databaseHook", async () => {
    const adminEmail = `admin-${Date.now()}@university.edu`;
    process.env.ADMIN_EMAILS = adminEmail;

    const ctx = await auth.$context;
    const adminUser = await ctx.internalAdapter.createUser({
      name: "Admin User",
      email: adminEmail,
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    expect(adminUser.role).toBe("admin");

    // Cleanup
    await db.delete(schema.user).where(eq(schema.user.id, adminUser.id));
  });

  it("rejects forged or unsigned session cookies", async () => {
    const ctx = await auth.$context;
    const cookieName = ctx.authCookies.sessionToken.name;

    // A raw unsigned token or tampered token
    const headers = new Headers({
      cookie: `${cookieName}=forged_session_token_without_signature`,
    });

    const sessionData = await auth.api.getSession({
      headers,
    });

    expect(sessionData).toBeNull();
  });
});
