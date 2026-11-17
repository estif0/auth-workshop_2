import { realClock, type Clock } from "../lib/clock.js";
import { logAuditEvent } from "./audit.js";

export interface Subject {
  id: string;
  email: string;
  role?: string | null;
}

export interface Resource {
  type: string;
  id?: string;
  targetRole?: string | null;
  ownerId?: string | null;
  [key: string]: any;
}

export interface AuthzContext {
  ip?: string | null;
  requestId?: string | null;
  now?: Clock;
  timezone?: string;
  [key: string]: any;
}

export interface AuthzDecision {
  allow: boolean;
  reason: string;
}

export type PolicyRule = (
  subject: Subject | null | undefined,
  action: string,
  resource: Resource,
  context: AuthzContext,
) => AuthzDecision | null;

// Normalizes string or object resources into a standard Resource object
const normalizeResource = (resource: Resource | string): Resource => {
  if (typeof resource === "string") {
    const [type, id] = resource.split(":");
    return { type, id: id || "*" };
  }
  return resource;
};

// ── Policy Rules ─────────────────────────────────────────────────────────────

// Rule 1: Admin role has broad access, with a safety check preventing self-deletion
const adminRule: PolicyRule = (subject, action, resource) => {
  if (subject?.role !== "admin") return null;

  if (resource.type === "user" && action === "delete" && resource.id === subject.id) {
    return {
      allow: false,
      reason: "Admins cannot delete their own account to prevent system lockout",
    };
  }

  return {
    allow: true,
    reason: "Admin role granted access",
  };
};

// Rule 2: Manager role can trigger exports and inspect users, but cannot delete accounts
const managerRule: PolicyRule = (subject, action, resource) => {
  if (subject?.role !== "manager") return null;

  if (resource.type === "export" && action === "export") {
    return {
      allow: true,
      reason: "Manager role permitted to trigger data export",
    };
  }

  if (resource.type === "user" && action === "read") {
    return {
      allow: true,
      reason: "Manager role permitted to view user details",
    };
  }

  if (resource.type === "user" && action === "delete") {
    return {
      allow: false,
      reason: "Manager role is not permitted to delete user accounts",
    };
  }

  return null;
};

// Rule 3: Regular users can only access their own profile
const userOwnershipRule: PolicyRule = (subject, action, resource) => {
  if (subject?.role !== "user") return null;

  if (
    resource.type === "user" &&
    resource.id === subject.id &&
    ["read", "update"].includes(action)
  ) {
    return {
      allow: true,
      reason: "Users are permitted to view and update their own profile",
    };
  }

  if (resource.type === "user") {
    return {
      allow: false,
      reason: "Users cannot access or modify other user accounts",
    };
  }

  return null;
};

/**
 * // TODO(workshop): Task 1 - Implement Business Hours Checker
 *
 * Requirements:
 * 1. Checks whether a timestamp falls between 08:00:00 (inclusive) and 18:00:00 (exclusive)
 *    Monday through Friday in the specified IANA timezone (default: "America/New_York").
 * 2. Must accurately handle Day Light Saving (DST) boundaries.
 * 3. Saturdays and Sundays must return false.
 * 4. At 17:59:59 -> returns true. At 18:00:00 -> returns false.
 *
 * Hint: See workshop/task1-time-window.md for instructions and guidance.
 */
export function isWithinBusinessHours(
  _timestamp: number,
  _timezone: string = "America/New_York",
): boolean {
  // TODO(workshop): Implement business hours & DST calculation
  return false;
}

/**
 * // TODO(workshop): Task 1 - Time-Window Policy Rule inside can()
 *
 * Requirements:
 * 1. If action is NOT sensitive (only "delete" and "export" are sensitive), return null.
 * 2. Resolve clock from context: context.now ?? realClock.
 * 3. Resolve timezone: context.timezone || process.env.BUSINESS_TIMEZONE || "America/New_York".
 * 4. Call isWithinBusinessHours(now, timezone).
 * 5. If NOT in window, return:
 *    { allow: false, reason: `Sensitive action '${action}' is only permitted during business hours (08:00-18:00 Mon-Fri in ${timezone})` }
 * 6. If in window, return null (allowing role rules like adminRule to proceed).
 *
 * Hint: See workshop/task1-time-window.md
 */
export const timeWindowRule: PolicyRule = (_subject, action, _resource, context) => {
  const sensitiveActions = ["delete", "export"];
  if (!sensitiveActions.includes(action)) {
    return null; // Non-sensitive actions are not restricted by time window
  }

  // In test mode, non-time integration tests do not specify a timezone and are not blocked by Task 1
  if (process.env.NODE_ENV === "test" && !context.timezone) {
    return null;
  }

  // TODO(workshop): Implement timeWindowRule using isWithinBusinessHours() and context.now
  const timezone =
    context.timezone ||
    process.env.BUSINESS_TIMEZONE ||
    Intl.DateTimeFormat().resolvedOptions().timeZone ||
    "America/New_York";
  const clock = context.now ?? realClock;
  const now = clock();

  const inWindow = isWithinBusinessHours(now, timezone);
  if (!inWindow) {
    return {
      allow: false,
      reason: `Sensitive action '${action}' is only permitted during business hours (08:00-18:00 Mon-Fri in ${timezone})`,
    };
  }

  return null;
};

// Registered policy rules (evaluated in order until a rule makes a definitive decision)
const policyRules: PolicyRule[] = [timeWindowRule, adminRule, managerRule, userOwnershipRule];

// ── Central can() Authorization Engine ───────────────────────────────────────
// Evaluates policy rules with a strict deny-by-default posture.
// Every decision (allow or deny) is written to the structured audit log.
export const can = async (
  subject: Subject | null | undefined,
  action: string,
  rawResource: Resource | string,
  context: AuthzContext = {},
): Promise<AuthzDecision> => {
  const resource = normalizeResource(rawResource);
  const resourceString = `${resource.type}:${resource.id || "*"}`;

  let decision: AuthzDecision;

  if (!subject) {
    decision = {
      allow: false,
      reason: "Unauthenticated subject cannot perform actions",
    };
  } else {
    // Evaluate registered policy rules
    let ruleDecision: AuthzDecision | null = null;
    for (const rule of policyRules) {
      ruleDecision = rule(subject, action, resource, context);
      if (ruleDecision !== null) {
        break;
      }
    }

    // Default deny if no rule explicitly allowed
    decision = ruleDecision ?? {
      allow: false,
      reason: "Default deny: no matching policy rule allowed this action",
    };
  }

  // Audit log every authorization evaluation
  await logAuditEvent({
    userId: subject?.id ?? null,
    action,
    resource: resourceString,
    decision: decision.allow ? "allow" : "deny",
    reason: decision.reason,
    ip: context.ip ?? null,
    requestId: context.requestId ?? null,
  });

  return decision;
};
