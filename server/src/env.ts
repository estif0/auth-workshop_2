// Validates env vars at startup using Zod.
// The server won't start if anything is missing or malformed.
// If not already loaded (e.g. CLI tools like better-auth or drizzle-kit),
// dotenv loads the root .env file.
import { config } from "dotenv";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { z } from "zod";

if (!process.env.DATABASE_URL) {
  const dir = fileURLToPath(new URL(".", import.meta.url));
  config({ path: resolve(dir, "../../.env") });
}

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
