import { randomUUID } from "node:crypto";
import { db } from "../db/index.js";
import { auditLogs } from "../db/schema.js";
import { logger } from "../middleware/logger.js";
import { getRequestId } from "../middleware/requestId.js";

export interface AuditEvent {
  userId?: string | null;
  action: string;
  resource: string;
  decision: "allow" | "deny";
  reason: string;
  ip?: string | null;
  requestId?: string | null;
}

// Writes structured audit records to both the Pino log stream and PostgreSQL audit_logs table.
// Extracts the active requestId automatically from AsyncLocalStorage.
export const logAuditEvent = async (event: AuditEvent): Promise<void> => {
  const requestId = event.requestId ?? getRequestId() ?? null;
  const id = randomUUID();

  // 1. Structured log via Pino
  logger.info(
    {
      audit: true,
      auditId: id,
      requestId,
      userId: event.userId ?? null,
      action: event.action,
      resource: event.resource,
      decision: event.decision,
      reason: event.reason,
      ip: event.ip ?? null,
    },
    `AUDIT [${event.decision.toUpperCase()}] ${event.action} on ${event.resource} by ${event.userId || "anonymous"} - ${event.reason}`,
  );

  // 2. Insert into PostgreSQL audit_logs table
  try {
    await db.insert(auditLogs).values({
      id,
      requestId,
      userId: event.userId ?? null,
      action: event.action,
      resource: event.resource,
      decision: event.decision,
      reason: event.reason,
      ip: event.ip ?? null,
      createdAt: new Date(),
    });
  } catch (error) {
    logger.error({ error, event }, "Failed to persist audit log to database");
  }
};
