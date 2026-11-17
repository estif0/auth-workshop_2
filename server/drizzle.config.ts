// Drizzle Kit reads this to know where the schema is and how to connect.
// dotenv is loaded explicitly because drizzle-kit runs as a separate process
// and doesn't inherit tsx's --env-file flag.
import { config } from "dotenv";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { defineConfig } from "drizzle-kit";

const dir = fileURLToPath(new URL(".", import.meta.url));
config({ path: resolve(dir, "../.env") });

export default defineConfig({
  out: "./drizzle",          // SQL migration files — committed to git
  schema: "./src/db/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
});
