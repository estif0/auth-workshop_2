# Workshop Task 2: Step-Up Authentication Middleware (`requireFreshAuth`)

## Objective
Implement Express middleware that forces step-up re-authentication on sensitive endpoints. If a user's session was created more than **5 minutes (300 seconds)** ago, reject the request with HTTP 403 and the specific error code `REAUTH_REQUIRED`.

---

## File to Edit
- `server/src/middleware/requireFreshAuth.ts`

---

## Background & Real-World Context
Why isn't a valid 7-day session enough?
Consider an unattended laptop at a coffee shop or a developer leaving their desk with their screen unlocked. An attacker walking by can access the dashboard.
If the attacker tries to view a dashboard, the active session works fine. But if they attempt a high-risk operation (e.g. deleting user accounts or downloading full database exports), the application demands proof of physical presence (password, biometric, or OIDC login) within the last 5 minutes.

---

## Requirements

1. **Prerequisite Check:** Ensure `req.session` and `req.user` exist (the preceding `authenticate` middleware must run first). If not, return HTTP `401 { error: "Authentication required", code: "UNAUTHORIZED" }`.
2. **Clock Resolution (Testability):**
   ```typescript
   const clock: Clock = (req.app?.locals?.clock as Clock) ?? defaultClock;
   const now = clock();
   ```
3. **Compute Session Age:**
   Use the session's creation timestamp:
   ```typescript
   const sessionCreatedAt = new Date(req.session.createdAt).getTime();
   const ageSeconds = Math.max(0, Math.floor((now - sessionCreatedAt) / 1000));
   ```
   *(Why `createdAt` and not `updatedAt`? `updatedAt` is constantly refreshed by sliding session keep-alives; using `updatedAt` would mean an active session is never stale!)*
4. **Freshness Enforcement:**
   If `ageSeconds > maxAgeSeconds`:
   - Log an audit event using `logAuditEvent()`:
     - `userId: req.user.id`
     - `action: "step_up_auth_required"`
     - `resource: req.originalUrl || req.path`
     - `decision: "deny"`
     - `reason: ...`
     - `ip: req.ip`
     - `requestId: req.id`
   - Return HTTP `403 Forbidden` with:
     ```json
     {
       "error": "Step-up re-authentication required",
       "code": "REAUTH_REQUIRED",
       "maxAgeSeconds": 300,
       "sessionAgeSeconds": 345
     }
     ```
5. **Session Still Fresh:** If `ageSeconds <= maxAgeSeconds`, call `next()`.

---

## Implementation Hints

```typescript
export const createRequireFreshAuth = (
  maxAgeSeconds: number = 300,
  defaultClock: Clock = realClock,
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.session || !req.user) {
      res.status(401).json({ error: "Authentication required", code: "UNAUTHORIZED" });
      return;
    }

    const clock: Clock = (req.app?.locals?.clock as Clock) ?? defaultClock;
    const now = clock();

    const createdAt = new Date(req.session.createdAt).getTime();
    const ageSeconds = Math.max(0, Math.floor((now - createdAt) / 1000));

    if (ageSeconds > maxAgeSeconds) {
      await logAuditEvent({
        userId: req.user.id,
        action: "step_up_auth_required",
        resource: req.originalUrl || req.path,
        decision: "deny",
        reason: `Session age (${ageSeconds}s) exceeds freshness threshold of ${maxAgeSeconds}s`,
        ip: req.ip,
        requestId: req.id,
      });

      res.status(403).json({
        error: "Step-up re-authentication required",
        code: "REAUTH_REQUIRED",
        maxAgeSeconds,
        sessionAgeSeconds: ageSeconds,
      });
      return;
    }

    next();
  };
};
```

---

## Verification
Run the task test suite:
```bash
npx vitest run test/step-up.test.ts
```
When your implementation is correct, all 5 tests will pass!
