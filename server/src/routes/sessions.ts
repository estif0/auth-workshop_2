import { Router } from "express";
import { and, desc, eq, gt, ne } from "drizzle-orm";
import { authenticate } from "../middleware/authenticate.js";
import { logAuditEvent } from "../services/audit.js";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";
import { auth } from "../auth.js";

export const sessionsRouter = Router();

// GET /api/sessions
// Lists all active, non-expired sessions for the authenticated user.
// Marks the session sending this request as `isCurrent: true`.
sessionsRouter.get("/", authenticate, async (req, res) => {
  const user = req.user!;
  const session = req.session!;

  const activeSessions = await db
    .select({
      id: schema.session.id,
      userId: schema.session.userId,
      ipAddress: schema.session.ipAddress,
      userAgent: schema.session.userAgent,
      createdAt: schema.session.createdAt,
      expiresAt: schema.session.expiresAt,
    })
    .from(schema.session)
    .where(
      and(
        eq(schema.session.userId, user.id),
        gt(schema.session.expiresAt, new Date()),
      ),
    )
    .orderBy(desc(schema.session.createdAt));

  const sessionsWithCurrent = activeSessions.map((s) => ({
    ...s,
    isCurrent: s.id === session.id,
  }));

  res.json({
    sessions: sessionsWithCurrent,
  });
});

// DELETE /api/sessions/:id
// Revokes a specific session.
// ⚠️ ANTI-IDOR SECURITY CHECK:
// Callers must only be allowed to revoke sessions that belong to them.
// Attempting to revoke another user's session results in HTTP 403 Forbidden
// and an audit log event.
sessionsRouter.delete("/:id", authenticate, async (req, res) => {
  const user = req.user!;
  const session = req.session!;
  const targetId = String(req.params.id);

  // 1. Locate target session in the database
  const [targetSession] = await db
    .select()
    .from(schema.session)
    .where(eq(schema.session.id, targetId));

  if (!targetSession) {
    res.status(404).json({
      error: "Session not found",
      code: "NOT_FOUND",
    });
    return;
  }

  // 2. Anti-IDOR ownership check: session must belong to caller
  if (targetSession.userId !== user.id) {
    await logAuditEvent({
      userId: user.id,
      action: "session_revoke_denied",
      resource: `session:${targetId}`,
      decision: "deny",
      reason: "IDOR prevention: session belongs to another user",
      ip: req.ip,
      requestId: req.id,
    });

    res.status(403).json({
      error: "You are not authorized to revoke a session belonging to another user",
      code: "FORBIDDEN",
    });
    return;
  }

  // 3. Delete session from PostgreSQL
  await db.delete(schema.session).where(eq(schema.session.id, targetId));

  // 4. If the caller revoked their current active session, clear the session cookie
  const wasCurrentSession = targetSession.id === session.id;
  if (wasCurrentSession) {
    const ctx = await auth.$context;
    res.clearCookie(ctx.authCookies.sessionToken.name, {
      path: ctx.authCookies.sessionToken.attributes.path || "/",
    });
  }

  // 5. Write structured audit log
  await logAuditEvent({
    userId: user.id,
    action: "session_revoke",
    resource: `session:${targetId}`,
    decision: "allow",
    reason: wasCurrentSession
      ? "Revoked current active session (logged out)"
      : "Revoked secondary active session",
    ip: req.ip,
    requestId: req.id,
  });

  res.json({
    success: true,
    message: "Session revoked successfully",
    revokedSessionId: targetId,
    wasCurrentSession,
  });
});

// POST /api/sessions/revoke-others
// Revokes all active sessions for the calling user EXCEPT the currently active one.
sessionsRouter.post("/revoke-others", authenticate, async (req, res) => {
  const user = req.user!;
  const session = req.session!;

  const deleted = await db
    .delete(schema.session)
    .where(
      and(
        eq(schema.session.userId, user.id),
        ne(schema.session.id, session.id),
      ),
    )
    .returning({ id: schema.session.id });

  await logAuditEvent({
    userId: user.id,
    action: "session_revoke_others",
    resource: `user:${user.id}:sessions`,
    decision: "allow",
    reason: `Revoked ${deleted.length} other active session(s)`,
    ip: req.ip,
    requestId: req.id,
  });

  res.json({
    success: true,
    message: `Successfully revoked ${deleted.length} other session(s)`,
    revokedCount: deleted.length,
  });
});
