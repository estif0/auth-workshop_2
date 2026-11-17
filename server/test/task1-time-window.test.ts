import { describe, it, expect } from "vitest";
import { can, isWithinBusinessHours, timeWindowRule } from "../src/services/authz.js";

describe("Workshop Task 1: Time-Window Policy Rule", () => {
  const admin = { id: "admin-time", email: "admin@test.com", role: "admin" };
  const user = { id: "user-time", email: "user@test.com", role: "user" };

  describe("isWithinBusinessHours Helper", () => {
    it("permits actions during normal weekday business hours (Wed 14:00)", () => {
      // Wednesday, June 10, 2026 at 18:00 UTC = 14:00 EDT
      const wednesdayAfternoon = new Date("2026-06-10T18:00:00Z").getTime();
      expect(isWithinBusinessHours(wednesdayAfternoon, "America/New_York")).toBe(true);
    });

    it("rejects actions on weekends (Saturday & Sunday)", () => {
      // Saturday, June 13, 2026 at 16:00 UTC = 12:00 EDT
      const saturdayNoon = new Date("2026-06-13T16:00:00Z").getTime();
      expect(isWithinBusinessHours(saturdayNoon, "America/New_York")).toBe(false);

      // Sunday, June 14, 2026 at 16:00 UTC = 12:00 EDT
      const sundayNoon = new Date("2026-06-14T16:00:00Z").getTime();
      expect(isWithinBusinessHours(sundayNoon, "America/New_York")).toBe(false);
    });

    it("enforces opening minute boundary (07:59:59 denied, 08:00:00 allowed)", () => {
      // In EDT (UTC-4):
      // 07:59:59 EDT = 11:59:59 UTC
      const beforeOpen = new Date("2026-06-10T11:59:59Z").getTime();
      expect(isWithinBusinessHours(beforeOpen, "America/New_York")).toBe(false);

      // 08:00:00 EDT = 12:00:00 UTC
      const atOpen = new Date("2026-06-10T12:00:00Z").getTime();
      expect(isWithinBusinessHours(atOpen, "America/New_York")).toBe(true);
    });

    it("enforces closing minute boundary (17:59:59 allowed, 18:00:00 denied)", () => {
      // In EDT (UTC-4):
      // 17:59:59 EDT = 21:59:59 UTC
      const lastSecond = new Date("2026-06-10T21:59:59Z").getTime();
      expect(isWithinBusinessHours(lastSecond, "America/New_York")).toBe(true);

      // 18:00:00 EDT = 22:00:00 UTC (exact minute the window closes)
      const closingMinute = new Date("2026-06-10T22:00:00Z").getTime();
      expect(isWithinBusinessHours(closingMinute, "America/New_York")).toBe(false);
    });

    it("correctly handles DST transition: Winter / Standard Time (EST = UTC-5)", () => {
      // Friday, March 6, 2026 (Before Spring Forward, UTC-5):
      // 08:00 EST = 13:00 UTC
      const openWinter = new Date("2026-03-06T13:00:00Z").getTime();
      expect(isWithinBusinessHours(openWinter, "America/New_York")).toBe(true);

      const oneSecondBefore = new Date("2026-03-06T12:59:59Z").getTime();
      expect(isWithinBusinessHours(oneSecondBefore, "America/New_York")).toBe(false);

      // 18:00 EST = 23:00 UTC
      const closeWinter = new Date("2026-03-06T23:00:00Z").getTime();
      expect(isWithinBusinessHours(closeWinter, "America/New_York")).toBe(false);

      const oneSecondBeforeClose = new Date("2026-03-06T22:59:59Z").getTime();
      expect(isWithinBusinessHours(oneSecondBeforeClose, "America/New_York")).toBe(true);
    });

    it("correctly handles DST transition: Summer / Daylight Saving Time (EDT = UTC-4)", () => {
      // Monday, March 9, 2026 (After Spring Forward, UTC-4):
      // Notice: 08:00 EDT is now 12:00 UTC (not 13:00 UTC)!
      const openSummer = new Date("2026-03-09T12:00:00Z").getTime();
      expect(isWithinBusinessHours(openSummer, "America/New_York")).toBe(true);

      const oneSecondBefore = new Date("2026-03-09T11:59:59Z").getTime();
      expect(isWithinBusinessHours(oneSecondBefore, "America/New_York")).toBe(false);

      // 18:00 EDT is now 22:00 UTC
      const closeSummer = new Date("2026-03-09T22:00:00Z").getTime();
      expect(isWithinBusinessHours(closeSummer, "America/New_York")).toBe(false);
    });
  });

  describe("can() Integration with Time-Window Policy", () => {
    it("denies sensitive actions (delete, export) when outside business hours", async () => {
      // Midnight in New York
      const midnightClock = () => new Date("2026-06-10T04:00:00Z").getTime(); // 00:00 EDT

      const deleteDecision = await can(
        admin,
        "delete",
        { type: "user", id: "other-user" },
        { now: midnightClock, timezone: "America/New_York" },
      );
      expect(deleteDecision.allow).toBe(false);
      expect(deleteDecision.reason).toContain("business hours");

      const exportDecision = await can(
        admin,
        "export",
        { type: "export" },
        { now: midnightClock, timezone: "America/New_York" },
      );
      expect(exportDecision.allow).toBe(false);
      expect(exportDecision.reason).toContain("business hours");
    });

    it("allows sensitive actions when inside business hours", async () => {
      // 14:00 EDT on Wednesday
      const businessClock = () => new Date("2026-06-10T18:00:00Z").getTime();

      const exportDecision = await can(
        admin,
        "export",
        { type: "export" },
        { now: businessClock, timezone: "America/New_York" },
      );
      expect(exportDecision.allow).toBe(true);
      expect(exportDecision.reason).toContain("Admin role granted access");
    });

    it("does NOT restrict non-sensitive actions outside business hours", async () => {
      // Midnight in New York
      const midnightClock = () => new Date("2026-06-10T04:00:00Z").getTime();

      // Regular user reading own profile at midnight -> allowed
      const readDecision = await can(
        user,
        "read",
        { type: "user", id: "user-time" },
        { now: midnightClock, timezone: "America/New_York" },
      );
      expect(readDecision.allow).toBe(true);
    });
  });
});
