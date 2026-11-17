import type { Request, Response, NextFunction } from "express";
import { realClock, type Clock } from "../lib/clock.js";

/**
 * // TODO(workshop): Task 2 - Implement requireFreshAuth Middleware (Step-Up Auth)
 *
 * Requirements:
 * 1. Verify req.session and req.user exist (return 401 if missing).
 * 2. Resolve clock: (req.app?.locals?.clock as Clock) ?? defaultClock.
 * 3. Calculate session age in seconds:
 *    const createdAt = new Date(req.session.createdAt).getTime();
 *    const ageSeconds = Math.max(0, Math.floor((now - createdAt) / 1000));
 * 4. If ageSeconds > maxAgeSeconds:
 *    a. Log audit event: { userId, action: "step_up_auth_required", resource, decision: "deny", reason, ip, requestId }
 *    b. Return HTTP 403 Forbidden with JSON:
 *       {
 *         error: "Step-up re-authentication required",
 *         code: "REAUTH_REQUIRED",
 *         maxAgeSeconds,
 *         sessionAgeSeconds: ageSeconds
 *       }
 * 5. If ageSeconds <= maxAgeSeconds: call next().
 *
 * Hint: See workshop/task2-fresh-auth.md for guidance and examples.
 */
export const createRequireFreshAuth = (
  _maxAgeSeconds: number = 300,
  _defaultClock: Clock = realClock,
) => {
  return async (_req: Request, res: Response, _next: NextFunction): Promise<void> => {
    // TODO(workshop): Implement step-up freshness check
    res.status(403).json({
      error: "TODO(workshop): requireFreshAuth middleware not implemented",
      code: "NOT_IMPLEMENTED",
    });
  };
};

// Default instance for application routes (5 minutes / 300s window)
export const requireFreshAuth = createRequireFreshAuth(300);
