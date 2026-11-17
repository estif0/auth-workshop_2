import type { Request, Response, NextFunction } from "express";
import { fromNodeHeaders } from "better-auth/node";
import { auth } from "../auth.js";

// Verifies the session cookie using Better Auth.
// If valid, attaches user and session to req. If missing or invalid, returns 401 Unauthorized.
export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const sessionData = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });

    if (!sessionData || !sessionData.session || !sessionData.user) {
      res.status(401).json({
        error: "Authentication required",
        code: "UNAUTHORIZED",
      });
      return;
    }

    req.user = sessionData.user;
    req.session = sessionData.session;
    next();
  } catch (_error) {
    res.status(401).json({
      error: "Authentication failed",
      code: "UNAUTHORIZED",
    });
  }
};
