import { Router } from "express";
import { desc } from "drizzle-orm";
import { authenticate } from "../middleware/authenticate.js";
import { requireRole } from "../middleware/requireRole.js";
import { db } from "../db/index.js";
import * as schema from "../db/schema.js";

export const adminRouter = Router();

// GET /api/admin/users — Lists all users in the system.
// Strictly admin-only (returns 401 if unauthenticated, 403 if not admin).
adminRouter.get("/users", authenticate, requireRole("admin"), async (_req, res) => {
  const allUsers = await db
    .select({
      id: schema.user.id,
      name: schema.user.name,
      email: schema.user.email,
      role: schema.user.role,
      emailVerified: schema.user.emailVerified,
      createdAt: schema.user.createdAt,
    })
    .from(schema.user);

  res.json({
    users: allUsers,
  });
});

// GET /api/admin/audit-logs — Returns recent structured audit logs.
// Strictly admin-only.
adminRouter.get("/audit-logs", authenticate, requireRole("admin"), async (_req, res) => {
  const logs = await db
    .select()
    .from(schema.auditLogs)
    .orderBy(desc(schema.auditLogs.createdAt))
    .limit(50);

  res.json({
    auditLogs: logs,
  });
});

