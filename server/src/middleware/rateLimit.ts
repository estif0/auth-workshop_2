import { rateLimit } from "express-rate-limit";
import { env } from "../env.js";

// General rate limiter for standard API endpoints (100 requests per 15 minutes).
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skip: () => env.NODE_ENV === "test", // Skip during automated test suites
  handler: (_req, res, _next, options) => {
    res.status(options.statusCode).json({
      error: "Too many requests, please try again later",
      code: "RATE_LIMITED",
    });
  },
});

// Stricter rate limiter for authentication routes (20 requests per 15 minutes)
// to prevent brute-force and credential abuse.
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skip: () => env.NODE_ENV === "test",
  handler: (_req, res, _next, options) => {
    res.status(options.statusCode).json({
      error: "Too many authentication attempts, please try again later",
      code: "AUTH_RATE_LIMITED",
    });
  },
});
