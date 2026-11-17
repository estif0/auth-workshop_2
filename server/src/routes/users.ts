import { Router } from "express";
import { eq } from "drizzle-orm";
import { authenticate } from "../middleware/authenticate.js";
import { requireRole } from "../middleware/requireRole.js";
import { requireFreshAuth } from "../middleware/requireFreshAuth.js";
import { can } from "../services/authz.js";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";

export const usersRouter = Router();

// DELETE /api/users/:id
// Requires:
//   1. authenticate: caller must hold an active session cookie (401 on failure)
//   2. requireRole("admin"): coarse-grained role check (403 on failure)
//   3. requireFreshAuth: step-up auth check (session < 5 min old, 403 REAUTH_REQUIRED on failure)
//   4. can(subject, "delete", { type: "user", id }): fine-grained ABAC policy rule
//      (e.g., prevents admin from deleting their own account to prevent lockout)
usersRouter.delete("/:id", authenticate, requireRole("admin"), requireFreshAuth, async (req, res) => {
  const targetId = String(req.params.id);

  // Evaluate fine-grained authorization engine
  const decision = await can(
    req.user,
    "delete",
    { type: "user", id: targetId },
    { ip: req.ip, requestId: req.id },
  );

  if (!decision.allow) {
    res.status(403).json({
      error: decision.reason,
      code: "FORBIDDEN",
    });
    return;
  }

  // Verify target user exists in the database
  const [existingUser] = await db
    .select()
    .from(schema.user)
    .where(eq(schema.user.id, targetId));

  if (!existingUser) {
    res.status(404).json({
      error: "User not found",
      code: "NOT_FOUND",
    });
    return;
  }

  // Delete user (foreign key constraints cascade to sessions and accounts)
  await db.delete(schema.user).where(eq(schema.user.id, targetId));

  res.json({
    success: true,
    message: `User ${targetId} deleted successfully`,
    deletedUserId: targetId,
  });
});
