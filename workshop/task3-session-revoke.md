# Workshop Task 3: Session Revocation & Anti-IDOR Ownership Check

## Objective
Implement session revocation endpoints (`DELETE /api/sessions/:id` and `POST /api/sessions/revoke-others`) with strict **Insecure Direct Object Reference (IDOR)** protection and structured audit logging.

---

## File to Edit
- `server/src/routes/sessions.ts`

---

## Background & Real-World Context
What is an IDOR vulnerability in session management?
If an endpoint simply executes `DELETE FROM session WHERE id = :id` without verifying *who owns the session*, any authenticated user can send random UUIDs or sniffed session IDs and terminate sessions belonging to other users (or even administrators!).

**Security Invariant:** A user may ONLY revoke a session that belongs to their own user account (`targetSession.userId === req.user.id`).

---

## Requirements

### 1. `DELETE /api/sessions/:id`
- Locate the target session by ID in PostgreSQL (`db.select().from(schema.session).where(eq(schema.session.id, targetId))`).
- If target session is not found: return HTTP `404 { error: "Session not found", code: "NOT_FOUND" }`.
- **Anti-IDOR Ownership Check:**
  - Verify `targetSession.userId === req.user.id`.
  - If they do NOT match:
    - Log audit event with `action: "session_revoke_denied"`, `decision: "deny"`, and `reason: "IDOR prevention: session belongs to another user"`.
    - Return HTTP `403 Forbidden` with:
      ```json
      {
        "error": "You are not authorized to revoke a session belonging to another user",
        "code": "FORBIDDEN"
      }
      ```
- Delete the session from PostgreSQL (`db.delete(schema.session).where(...)`).
- **Self-Revocation Handling:**
  - If `targetSession.id === req.session.id` (user revoked their current session):
    - Clear the session cookie using `res.clearCookie()`.
- Log audit event with `action: "session_revoke"`, `decision: "allow"`.
- Return HTTP `200 OK`:
  ```json
  {
    "success": true,
    "message": "Session revoked successfully",
    "revokedSessionId": targetId,
    "wasCurrentSession": boolean
  }
  ```

### 2. `POST /api/sessions/revoke-others`
- Delete all sessions belonging to `req.user.id` EXCEPT the caller's current session (`userId === req.user.id AND id !== req.session.id`).
- Log audit event with `action: "session_revoke_others"`, `decision: "allow"`, and `reason: "Revoked N other active session(s)"`.
- Return HTTP `200 OK`:
  ```json
  {
    "success": true,
    "message": "Successfully revoked N other session(s)",
    "revokedCount": number
  }
  ```

---

## Implementation Hints

```typescript
import { and, eq, ne } from "drizzle-orm";
import { auth } from "../auth.js";

// DELETE /api/sessions/:id
sessionsRouter.delete("/:id", authenticate, async (req, res) => {
  const user = req.user!;
  const session = req.session!;
  const targetId = String(req.params.id);

  const [targetSession] = await db
    .select()
    .from(schema.session)
    .where(eq(schema.session.id, targetId));

  if (!targetSession) {
    res.status(404).json({ error: "Session not found", code: "NOT_FOUND" });
    return;
  }

  // IDOR check
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

  await db.delete(schema.session).where(eq(schema.session.id, targetId));

  const wasCurrentSession = targetSession.id === session.id;
  if (wasCurrentSession) {
    const ctx = await auth.$context;
    res.clearCookie(ctx.authCookies.sessionToken.name, {
      path: ctx.authCookies.sessionToken.attributes.path || "/",
    });
  }

  await logAuditEvent({
    userId: user.id,
    action: "session_revoke",
    resource: `session:${targetId}`,
    decision: "allow",
    reason: wasCurrentSession ? "Revoked current session" : "Revoked secondary session",
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
```

---

## Verification
Run the task test suite:
```bash
npx vitest run test/sessions.test.ts
```
When your implementation is correct, all 8 tests will pass!
