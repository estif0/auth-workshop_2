import { Router } from "express";
import { authenticate } from "../middleware/authenticate.js";
import { requireRole } from "../middleware/requireRole.js";
import { requireFreshAuth } from "../middleware/requireFreshAuth.js";
import { can } from "../services/authz.js";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";

export const exportRouter = Router();

// POST /api/export
// Requires:
//   1. authenticate: caller must hold an active session cookie (401 on failure)
//   2. requireRole("admin", "manager"): coarse-grained role check (403 on failure)
//   3. requireFreshAuth: step-up auth check (session < 5 min old, 403 REAUTH_REQUIRED on failure)
//   4. can(subject, "export", { type: "export" }): fine-grained policy check
exportRouter.post("/", authenticate, requireRole("admin", "manager"), requireFreshAuth, async (req, res) => {
  // Evaluate fine-grained authorization engine
  const decision = await can(
    req.user,
    "export",
    { type: "export" },
    {
      ip: req.ip,
      requestId: req.id,
      now: req.app?.locals?.clock,
    },
  );

  if (!decision.allow) {
    res.status(403).json({
      error: decision.reason,
      code: "FORBIDDEN",
    });
    return;
  }

  // Generate lightweight export summary
  const users = await db
    .select({
      id: schema.user.id,
      name: schema.user.name,
      email: schema.user.email,
      role: schema.user.role,
      createdAt: schema.user.createdAt,
    })
    .from(schema.user);

  res.json({
    success: true,
    exportedAt: new Date().toISOString(),
    recordCount: users.length,
    data: users,
  });
});
