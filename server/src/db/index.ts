// Drizzle database connection.
// Passing the URL string lets Drizzle manage the pg connection pool internally.
import { drizzle } from "drizzle-orm/node-postgres";
import { env } from "../env.js";

export const db = drizzle(env.DATABASE_URL);
