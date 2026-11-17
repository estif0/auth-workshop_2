import type { Request, Response, NextFunction } from "express";

export type Role = "admin" | "manager" | "user";

// Role-based access control middleware:
// - 401 Unauthorized: caller identity is unverified or missing (authenticate first).
// - 403 Forbidden: caller identity is established, but lacks the necessary authorization.
export const requireRole = (...allowedRoles: Role[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({
        error: "Authentication required",
        code: "UNAUTHORIZED",
      });
      return;
    }

    const currentRole = (req.user.role || "user") as Role;
    if (!allowedRoles.includes(currentRole)) {
      res.status(403).json({
        error: "Forbidden: insufficient permissions",
        code: "FORBIDDEN",
        requiredRoles: allowedRoles,
        currentRole,
      });
      return;
    }

    next();
  };
};
