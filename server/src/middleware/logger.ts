import pino from "pino";
import type { Request, Response, NextFunction } from "express";
import { getRequestId } from "./requestId.js";
import { env } from "../env.js";

// Pino logger configured with strict redaction of credentials, cookies, and tokens.
// Hard Rule 5: Never log secrets, tokens, cookies or passwords.
export const logger = pino({
  level: env.NODE_ENV === "test" ? "silent" : "info",
  redact: {
    paths: [
      "req.headers.cookie",
      "req.headers.authorization",
      "headers.cookie",
      "headers.authorization",
      "cookie",
      "authorization",
      "*.password",
      "*.token",
      "*.secret",
      "password",
      "token",
      "secret",
      "accessToken",
      "refreshToken",
      "idToken",
    ],
    censor: "[REDACTED]",
  },
  mixin() {
    const requestId = getRequestId();
    return requestId ? { requestId } : {};
  },
});

// Structured HTTP access logger logging status code, duration, user, and request ID.
export const httpLogger = (req: Request, res: Response, next: NextFunction) => {
  const startTime = Date.now();

  res.on("finish", () => {
    const durationMs = Date.now() - startTime;
    logger.info(
      {
        method: req.method,
        url: req.originalUrl || req.url,
        statusCode: res.statusCode,
        durationMs,
        userId: req.user?.id,
        ip: req.ip,
      },
      `${req.method} ${req.originalUrl || req.url} ${res.statusCode} - ${durationMs}ms`,
    );
  });

  next();
};
