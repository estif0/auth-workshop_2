import { Router } from "express";
import { and, desc, eq, gt } from "drizzle-orm";
import { authenticate } from "../middleware/authenticate.js";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";

export const sessionsRouter = Router();

// GET /api/sessions (Pre-built)
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

// // TODO(workshop): Task 3 - Implement DELETE /api/sessions/:id with Anti-IDOR Protection
//
// Requirements:
// 1. Locate session in database by targetId (return 404 NOT_FOUND if missing).
// 2. CRITICAL: Anti-IDOR ownership check. If targetSession.userId !== req.user.id:
//    - Log audit event: action "session_revoke_denied", decision "deny", reason "IDOR prevention: session belongs to another user"
//    - Return HTTP 403 Forbidden with code "FORBIDDEN" and error "You are not authorized to revoke a session belonging to another user".
// 3. Delete target session from PostgreSQL using db.delete(schema.session).
// 4. If targetSession.id === req.session.id: clear the session cookie (res.clearCookie).
// 5. Log audit event: action "session_revoke", decision "allow".
// 6. Return 200 OK: { success: true, message: "Session revoked successfully", revokedSessionId: targetId, wasCurrentSession }.
//
// Hint: See workshop/task3-session-revoke.md for guidance and examples.
sessionsRouter.delete("/:id", authenticate, async (_req, res) => {
  // TODO(workshop): Implement DELETE /api/sessions/:id with ownership check and audit logging
  res.status(501).json({
    error: "TODO(workshop): DELETE /api/sessions/:id not implemented yet",
    code: "NOT_IMPLEMENTED",
  });
});

// // TODO(workshop): Task 3 - Implement POST /api/sessions/revoke-others
//
// Requirements:
// 1. Delete all sessions belonging to user where userId === req.user.id AND id !== req.session.id.
// 2. Log audit event: action "session_revoke_others", decision "allow".
// 3. Return 200 OK: { success: true, message: "Successfully revoked N other session(s)", revokedCount: N }.
//
// Hint: See workshop/task3-session-revoke.md for guidance and examples.
sessionsRouter.post("/revoke-others", authenticate, async (_req, res) => {
  // TODO(workshop): Implement POST /api/sessions/revoke-others
  res.status(501).json({
    error: "TODO(workshop): POST /api/sessions/revoke-others not implemented yet",
    code: "NOT_IMPLEMENTED",
  });
});
