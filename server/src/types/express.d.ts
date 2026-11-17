import type { auth } from "../auth.js";

type AuthSession = typeof auth.$Infer.Session;

declare global {
  namespace Express {
    interface Request {
      id?: string;
      user?: AuthSession["user"];
      session?: AuthSession["session"];
    }
  }
}
