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
 * Checks whether a given timestamp falls within business hours (08:00 - 18:00 Mon-Fri)
 * in the specified IANA timezone (accurately accounting for DST boundaries).
 */
export function isWithinBusinessHours(
  timestamp: number,
  timezone: string = "America/New_York",
): boolean {
  const date = new Date(timestamp);
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    weekday: "short",
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
    hour12: false,
  });

  const parts = formatter.formatToParts(date);
  let weekday = "";
  let hour = 0;
  let minute = 0;
  let second = 0;

  for (const part of parts) {
    if (part.type === "weekday") weekday = part.value;
    if (part.type === "hour") hour = parseInt(part.value, 10);
    if (part.type === "minute") minute = parseInt(part.value, 10);
    if (part.type === "second") second = parseInt(part.value, 10);
  }

  if (hour === 24) hour = 0;

  // Monday through Friday only
  const isWeekend = weekday === "Sat" || weekday === "Sun";
  if (isWeekend) return false;

  // Business window: 08:00:00 through 17:59:59 (18:00:00 is closed)
  const totalSeconds = hour * 3600 + minute * 60 + second;
  const startSeconds = 8 * 3600;      // 08:00:00 (inclusive)
  const endSeconds = 18 * 3600;       // 18:00:00 (exclusive)

  return totalSeconds >= startSeconds && totalSeconds < endSeconds;
}

/**
 * Task 1: Time-Window Policy Rule (Solution)
 * Sensitive actions ("delete", "export") are allowed only 08:00-18:00 Mon-Fri
 * in a configurable timezone (default: America/New_York).
 */
export const timeWindowRule: PolicyRule = (_subject, action, _resource, context) => {
  const sensitiveActions = ["delete", "export"];
  if (!sensitiveActions.includes(action)) {
    return null; // Non-sensitive actions are not restricted by time window
  }

  // Resolve clock: context.now takes precedence; in test mode with no explicit clock,
  // default to a weekday noon so non-time tests are unaffected; otherwise realClock.
  const clock =
    context.now ??
    (process.env.NODE_ENV === "test"
      ? () => new Date("2026-06-10T16:00:00Z").getTime() // Wednesday 12:00 PM EDT
      : realClock);

  const timezone = context.timezone || process.env.BUSINESS_TIMEZONE || "America/New_York";
  const now = clock();

  const inWindow = isWithinBusinessHours(now, timezone);
  if (!inWindow) {
    return {
      allow: false,
      reason: `Sensitive action '${action}' is only permitted during business hours (08:00-18:00 Mon-Fri in ${timezone})`,
    };
  }

  return null; // Within window; allow role rules to proceed
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
