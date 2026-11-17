import type { Request, Response, NextFunction } from "express";
import { realClock, type Clock } from "../lib/clock.js";
import { logAuditEvent } from "../services/audit.js";

/**
 * createRequireFreshAuth
 *
 * Factory that returns an Express middleware enforcing session freshness
 * (step-up re-authentication) for sensitive endpoints.
 *
 * @param maxAgeSeconds Maximum acceptable session age in seconds (default: 300 = 5 minutes)
 * @param defaultClock Injected clock source (default: realClock)
 */
export const createRequireFreshAuth = (
  maxAgeSeconds: number = 300,
  defaultClock: Clock = realClock,
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // 1. Session must be loaded by preceding authenticate middleware
    if (!req.session || !req.user) {
      res.status(401).json({
        error: "Authentication required",
        code: "UNAUTHORIZED",
      });
      return;
    }

    // 2. Resolve clock (app-level dynamic clock override takes precedence for tests/demos)
    const clock: Clock = (req.app?.locals?.clock as Clock) ?? defaultClock;
    const now = clock();

    // 3. Compute session age relative to session creation time
    const sessionCreatedAt = new Date(req.session.createdAt).getTime();
    const ageSeconds = Math.max(0, Math.floor((now - sessionCreatedAt) / 1000));

    // 4. Reject if session is older than the freshness threshold
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

// Default middleware instance with 5-minute (300 seconds) freshness window
export const requireFreshAuth = createRequireFreshAuth(300);
