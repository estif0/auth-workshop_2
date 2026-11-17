// Validates env vars at startup using Zod.
// The server won't start if anything is missing or malformed.
// This catches "forgot to set BETTER_AUTH_SECRET" before the first request.
import { z } from "zod";

const schema = z.object({
  PORT: z.coerce.number().default(4000),
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  // Phase 3 — Better Auth
  BETTER_AUTH_SECRET: z.string().optional(),
  BETTER_AUTH_URL: z.string().optional(),
  // Phase 3 — Google OAuth
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  // Phase 3 — Role assignment
  ADMIN_EMAILS: z.string().optional(),
  // Phase 3 — Dev fallback login
  DEV_LOGIN_ENABLED: z
    .string()
    .optional()
    .transform((v) => v === "true"),
});

export const env = schema.parse(process.env);
export type Env = z.infer<typeof schema>;
