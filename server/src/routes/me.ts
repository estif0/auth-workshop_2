import { Router } from "express";
import { authenticate } from "../middleware/authenticate.js";

export const meRouter = Router();

// GET /api/me — Returns current authenticated user and session details.
// Protected by authenticate middleware (returns 401 if unauthenticated).
meRouter.get("/me", authenticate, (req, res) => {
  res.json({
    user: req.user,
    session: req.session,
  });
});
