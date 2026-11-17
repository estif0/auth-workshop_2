import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { env } from "./env.js";
import { db } from "./db/index.js";
import * as schema from "./db/schema.js";

// Parse list of admin emails from env var (case-insensitive)
export const getAdminEmails = (): string[] => {
  const raw = process.env.ADMIN_EMAILS ?? env.ADMIN_EMAILS ?? "";
  return raw
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
};

export const auth = betterAuth({
  baseURL: env.BETTER_AUTH_URL || `http://localhost:${env.PORT}`,
  secret:
    env.BETTER_AUTH_SECRET ||
    "workshop-default-secret-at-least-32-chars-long",
  database: drizzleAdapter(db, {
    provider: "pg",
    schema,
  }),
  user: {
    additionalFields: {
      role: {
        type: "string",
        defaultValue: "user",
        required: false,
      },
    },
  },
  databaseHooks: {
    user: {
      create: {
        // Automatically elevate user to "admin" if their email matches ADMIN_EMAILS
        before: async (user) => {
          const admins = getAdminEmails();
          const isAdmin = admins.includes(user.email.toLowerCase());
          return {
            data: {
              ...user,
              role: isAdmin ? "admin" : "user",
            },
          };
        },
      },
    },
  },
  session: {
    // 7 days total lifetime
    expiresIn: 60 * 60 * 24 * 7,
    // Throttle DB updates to at most once per 24 hours
    updateAge: 60 * 60 * 24,
    // Step-up freshness window: 5 minutes (300 seconds)
    freshAge: 5 * 60,
    // Explicitly disable cookieCache so server session revocation takes effect immediately
    cookieCache: {
      enabled: false,
    },
  },
  advanced: {
    cookiePrefix: "auth-workshop",
    defaultCookieAttributes: {
      httpOnly: true,
      sameSite: "lax",
      secure: env.NODE_ENV === "production",
      path: "/",
    },
  },
  trustedOrigins: ["http://localhost:5173", `http://localhost:${env.PORT}`],
  socialProviders: {
    google: {
      clientId: env.GOOGLE_CLIENT_ID || "",
      clientSecret: env.GOOGLE_CLIENT_SECRET || "",
    },
  },
});
