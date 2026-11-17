import { Router } from "express";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";
import { makeSignature } from "better-auth/crypto";
import { auth, getAdminEmails } from "../auth.js";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { env } from "../env.js";
import { isWithinBusinessHours } from "../services/authz.js";

export const devRouter = Router();

// Dev-only fallback login route — physically gated by DEV_LOGIN_ENABLED.
// Allows instructors and attendees to simulate login as any user or role
// without requiring Google Cloud credentials or internet connectivity.
devRouter.post("/login", async (req, res) => {
  const { email, name, role } = req.body;
  if (!email || typeof email !== "string") {
    res.status(400).json({ error: "Email is required" });
    return;
  }

  const normalizedEmail = email.trim().toLowerCase();
  const admins = getAdminEmails();
  const defaultRole = admins.includes(normalizedEmail) ? "admin" : "user";
  const userRole =
    role && ["admin", "manager", "user"].includes(role) ? role : defaultRole;

  // 1. Find or create user in the database
  const existingUsers = await db
    .select()
    .from(schema.user)
    .where(eq(schema.user.email, normalizedEmail))
    .limit(1);

  let currentUser = existingUsers[0];
  if (!currentUser) {
    const newUser = {
      id: randomUUID(),
      name: name || normalizedEmail.split("@")[0],
      email: normalizedEmail,
      emailVerified: true,
      image: null,
      role: userRole,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await db.insert(schema.user).values(newUser);
    currentUser = newUser;
  } else if (role && currentUser.role !== role) {
    await db
      .update(schema.user)
      .set({ role, updatedAt: new Date() })
      .where(eq(schema.user.id, currentUser.id));
    currentUser.role = role;
  }

  // 2. Create a real Better Auth session
  const ctx = await auth.$context;
  const session = await ctx.internalAdapter.createSession(currentUser.id);

  // If a simulated clock is active (tests/demos), synchronize session createdAt with simulated time
  if (req.app?.locals?.clock) {
    const simulatedDate = new Date(req.app.locals.clock());
    await db
      .update(schema.session)
      .set({ createdAt: simulatedDate })
      .where(eq(schema.session.id, session.id));
    session.createdAt = simulatedDate;
  }

  // 3. Generate HMAC signature for the session cookie
  // Better Auth expects: `${token}.${base64Signature}`
  const signature = await makeSignature(session.token, ctx.secret);
  const signedCookieValue = `${session.token}.${signature}`;

  // 4. Set the official Better Auth session cookie
  const cookieConfig = ctx.authCookies.sessionToken;
  res.cookie(cookieConfig.name, signedCookieValue, {
    httpOnly: cookieConfig.attributes.httpOnly,
    sameSite:
      (cookieConfig.attributes.sameSite?.toLowerCase() as
        | "lax"
        | "strict"
        | "none") || "lax",
    path: cookieConfig.attributes.path || "/",
    maxAge: cookieConfig.attributes.maxAge
      ? cookieConfig.attributes.maxAge * 1000
      : undefined,
    secure: env.NODE_ENV === "production",
  });

  res.json({
    success: true,
    user: currentUser,
    session: {
      id: session.id,
      expiresAt: session.expiresAt,
    },
  });
});

// GET /api/dev/clock — Returns active simulated or system time, timezone, and business hours status
devRouter.get("/clock", (req, res) => {
  const clock = (req.app.locals.clock as (() => number)) ?? (() => Date.now());
  const now = clock();
  const timezone =
    process.env.BUSINESS_TIMEZONE ||
    Intl.DateTimeFormat().resolvedOptions().timeZone ||
    "America/New_York";

  res.json({
    simulatedNow: new Date(now).toISOString(),
    timezone,
    inBusinessHours: isWithinBusinessHours(now, timezone),
    isOverridden: !!req.app.locals.clock,
  });
});

// POST /api/dev/clock — Dev-only clock manipulation for workshop demos and automated tests.
// Allows advancing simulated time (+305s for step-up), jumping to specific hours (14:00 or 02:00),
// or resetting back to real system time.
devRouter.post("/clock", (req, res) => {
  const { offsetSeconds, timestamp, reset, setHour } = req.body;
  const timezone =
    process.env.BUSINESS_TIMEZONE ||
    Intl.DateTimeFormat().resolvedOptions().timeZone ||
    "America/New_York";

  if (reset) {
    delete req.app.locals.clock;
    const now = Date.now();
    res.json({
      success: true,
      simulatedNow: new Date(now).toISOString(),
      timezone,
      inBusinessHours: isWithinBusinessHours(now, timezone),
      reset: true,
    });
    return;
  }

  if (typeof setHour === "number") {
    const target = new Date();
    // If today is a weekend, jump to a Wednesday so business hours simulation works as expected
    if (target.getDay() === 0 || target.getDay() === 6) {
      const dayDiff = (3 - target.getDay() + 7) % 7 || 7;
      target.setDate(target.getDate() + dayDiff);
    }
    target.setHours(setHour, 0, 0, 0);
    const targetTime = target.getTime();
    req.app.locals.clock = () => targetTime;
    res.json({
      success: true,
      simulatedNow: new Date(targetTime).toISOString(),
      timezone,
      inBusinessHours: isWithinBusinessHours(targetTime, timezone),
    });
    return;
  }

  if (typeof timestamp === "number") {
    req.app.locals.clock = () => timestamp;
    res.json({
      success: true,
      simulatedNow: new Date(timestamp).toISOString(),
      timezone,
      inBusinessHours: isWithinBusinessHours(timestamp, timezone),
    });
    return;
  }

  if (typeof offsetSeconds === "number") {
    const currentBase = req.app.locals.clock ? req.app.locals.clock() : Date.now();
    const targetTime = currentBase + offsetSeconds * 1000;
    req.app.locals.clock = () => targetTime;
    res.json({
      success: true,
      offsetSeconds,
      simulatedNow: new Date(targetTime).toISOString(),
      timezone,
      inBusinessHours: isWithinBusinessHours(targetTime, timezone),
    });
    return;
  }

  res.status(400).json({
    error: "Provide offsetSeconds, setHour, timestamp, or reset: true",
  });
});

