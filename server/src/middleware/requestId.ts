import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { Request, Response, NextFunction } from "express";

interface RequestStore {
  requestId: string;
}

export const requestContext = new AsyncLocalStorage<RequestStore>();

// Retrieves the current request ID from anywhere in the async execution tree
// without passing request objects down function arguments.
export const getRequestId = (): string | undefined => {
  return requestContext.getStore()?.requestId;
};

// Generates or propagates X-Request-Id, attaches it to the request/response,
// and enters the AsyncLocalStorage context for the remainder of the request lifecycle.
export const requestIdMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const incoming = req.headers["x-request-id"];
  const requestId =
    typeof incoming === "string" && incoming.trim()
      ? incoming.trim()
      : randomUUID();

  req.id = requestId;
  res.setHeader("X-Request-Id", requestId);

  requestContext.run({ requestId }, () => {
    next();
  });
};
