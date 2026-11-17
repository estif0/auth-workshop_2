// Re-export Better Auth tables (generated via `npx better-auth generate`)
export * from "./auth-schema.js";

import { pgTable, text, timestamp, index } from "drizzle-orm/pg-core";

// Custom audit log table for authorization decisions and security events
export const auditLogs = pgTable(
  "audit_logs",
  {
    id: text("id").primaryKey(),
    requestId: text("request_id"),
    userId: text("user_id"),
    action: text("action").notNull(),
    resource: text("resource").notNull(),
    decision: text("decision").notNull(), // "allow" | "deny"
    reason: text("reason").notNull(),
    ip: text("ip"),
    createdAt: timestamp("created_at").defaultNow().notNull(),
  },
  (table) => [
    index("audit_logs_user_id_idx").on(table.userId),
    index("audit_logs_created_at_idx").on(table.createdAt),
  ],
);

export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;
