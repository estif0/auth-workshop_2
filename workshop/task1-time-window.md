# Workshop Task 1: Time-Window Policy Rule (ABAC)

## Objective
Implement a context-aware Attribute-Based Access Control (ABAC) rule inside `can()` that restricts sensitive operations (`"delete"` and `"export"`) to official business hours: **08:00 to 18:00, Monday through Friday**, in a configurable timezone (default: `"America/New_York"`).

---

## File to Edit
- `server/src/services/authz.ts`

---

## Background & Real-World Context
Why do role-based permissions (RBAC) fall short for sensitive operations?
Even if an employee has the `"admin"` role, should they be able to export the company customer database or purge user records at 3:00 AM on a Sunday from an overseas IP address?
In Zero-Trust architectures, **context matters**:
- **Subject attributes:** Role, department, MFA status.
- **Action & Resource:** Exporting database records, deleting accounts.
- **Environment Context:** Time of day, day of week, geolocation, device posture.

---

## Requirements

### 1. `isWithinBusinessHours(timestamp: number, timezone: string): boolean`
- Evaluates whether the timestamp falls on a **weekday (Monday–Friday)**.
- Evaluates whether the local time is **between 08:00:00 (inclusive) and 18:00:00 (exclusive)**:
  - `07:59:59` → Closed (`false`)
  - `08:00:00` → Open (`true`)
  - `17:59:59` → Open (`true`)
  - `18:00:00` → Closed (`false` — the window closes at 18:00 sharp)
  - Saturday & Sunday → Closed (`false`)
- **Daylight Saving Time (DST):** Must accurately adjust for DST transitions (e.g. UTC-5 in winter vs. UTC-4 in summer for `America/New_York`).

### 2. `timeWindowRule: PolicyRule`
- Check if `action` is one of `["delete", "export"]`. If not, return `null` (allow standard read/profile operations to proceed unaffected).
- Resolve clock: use `context.now ?? realClock`.
- Resolve timezone: use `context.timezone || process.env.BUSINESS_TIMEZONE || "America/New_York"`.
- If outside business hours:
  Return `{ allow: false, reason: "Sensitive action '...' is only permitted during business hours (08:00-18:00 Mon-Fri in ...)" }`.
- If inside business hours:
  Return `null` (this lets subsequent role rules like `adminRule` or `managerRule` check role permissions).

---

## Implementation Hints

### Using `Intl.DateTimeFormat` for Timezone & DST
JavaScript's built-in `Intl.DateTimeFormat` can format any Unix timestamp into specific timezone components without external date libraries:

```typescript
const date = new Date(timestamp);
const formatter = new Intl.DateTimeFormat("en-US", {
  timeZone: timezone,
  weekday: "short",  // "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
  hour: "numeric",
  minute: "numeric",
  second: "numeric",
  hour12: false,     // 24-hour format: 0 to 23
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

// Watch out: Some ICU environments format midnight 00:00 as 24:00 with hour12: false
if (hour === 24) hour = 0;
```

### Checking Weekdays and Seconds Range
```typescript
const isWeekend = weekday === "Sat" || weekday === "Sun";
if (isWeekend) return false;

const totalSeconds = hour * 3600 + minute * 60 + second;
const startSeconds = 8 * 3600;  // 08:00:00
const endSeconds = 18 * 3600;   // 18:00:00

return totalSeconds >= startSeconds && totalSeconds < endSeconds;
```

---

## Verification
Run the task test suite:
```bash
npx vitest run test/task1-time-window.test.ts
```
When your implementation is correct, all 9 tests will pass!
