import { posix } from "node:path";
import type { Link, TransportRequest } from "../types.js";
import { GateError } from "../types.js";

function canonicalBody(input: unknown): { body: Record<string, unknown>; bytes: number } {
  try {
    const serialized = JSON.stringify(input);
    if (serialized === undefined) throw new Error("not serializable");
    const parsed: unknown = JSON.parse(serialized);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("body is not an object");
    }
    return { body: parsed as Record<string, unknown>, bytes: Buffer.byteLength(serialized, "utf8") };
  } catch {
    throw new GateError("REQUEST_SEMANTICS", "request body must be a finite JSON object");
  }
}

function finiteAmount(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new GateError("REQUEST_SEMANTICS", "operation amount must be a finite non-negative number");
  }
  return value;
}

function exactPath(path: string): string {
  if (!path.startsWith("/") || path.includes("\0") || posix.normalize(path) !== path) {
    throw new GateError("REQUEST_SEMANTICS", "transport path must be absolute and already normalized");
  }
  return path;
}

function requireClaimedOp(request: TransportRequest, actualOp: string): void {
  if (request.op !== actualOp) {
    throw new GateError(
      "REQUEST_SEMANTICS",
      `claimed op '${request.op}' does not match canonical operation '${actualOp}'`,
    );
  }
}

function assertCanarySemantics(
  link: Link,
  body: Record<string, unknown>,
  amount: number,
  labels: readonly string[],
): void {
  if (amount !== link.requirements.canary.expectedAmount ||
      body.destination !== link.requirements.canary.sink ||
      !labels.includes("canary")) {
    throw new GateError(
      "REQUEST_SEMANTICS",
      "canary operation does not match the link's required amount, sink, and marker",
    );
  }
}

function normalizeRest(link: Link, request: TransportRequest): TransportRequest {
  const path = exactPath(request.path);
  if (path === "/v1/health") {
    const method = (request.method ?? "GET").toUpperCase();
    if (method !== "GET" || request.body !== undefined) {
      throw new GateError("REQUEST_SEMANTICS", "REST health is exactly GET /v1/health without a body");
    }
    requireClaimedOp(request, "rest.health");
    return { op: "rest.health", path, method, bytes: 0, labels: [...(request.labels ?? [])] };
  }
  if (path !== "/v1/payments") {
    throw new GateError("REQUEST_SEMANTICS", `unknown REST route ${path}`);
  }
  const method = (request.method ?? "POST").toUpperCase();
  if (method !== "POST") {
    throw new GateError("REQUEST_SEMANTICS", "payments require POST /v1/payments");
  }
  const canonical = canonicalBody(request.body);
  const body = canonical.body;
  const opByKind: Record<string, string> = {
    canary: "rest.payment.canary",
    limited: "rest.payment.small",
    production: "rest.payment.create",
  };
  const actualOp = typeof body.kind === "string" ? opByKind[body.kind] : undefined;
  if (!actualOp) throw new GateError("REQUEST_SEMANTICS", "unknown REST payment body kind");
  requireClaimedOp(request, actualOp);
  const amount = finiteAmount(body.amount);
  const labels = [...(request.labels ?? [])];
  if (request.amount !== undefined && request.amount !== amount) {
    throw new GateError("REQUEST_SEMANTICS", "claimed amount does not match payment body");
  }
  if (actualOp === "rest.payment.canary") assertCanarySemantics(link, body, amount, labels);
  return {
    op: actualOp,
    path,
    method,
    body,
    amount,
    bytes: canonical.bytes,
    labels,
  };
}

function underPrefix(path: string, prefix: string): boolean {
  const normalizedPrefix = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return path.startsWith(normalizedPrefix);
}

function normalizeSftp(link: Link, request: TransportRequest): TransportRequest {
  const path = exactPath(request.path);
  const op = request.op;
  const known = new Set([
    "sftp.put.canary",
    "sftp.put.settlement",
    "sftp.list.quarantine",
    "sftp.list",
    "sftp.get",
  ]);
  if (!known.has(op)) throw new GateError("REQUEST_SEMANTICS", `unsupported SFTP operation ${op}`);

  const prefix = link.requirements.canary.pathPrefix ?? "/quarantine/canary/";
  if ((op === "sftp.put.canary" || op === "sftp.list.quarantine") && !underPrefix(path, prefix)) {
    throw new GateError("REQUEST_SEMANTICS", `operation ${op} must remain under ${prefix}`);
  }
  if (op.startsWith("sftp.list") || op === "sftp.get") {
    if (request.body !== undefined || request.amount !== undefined) {
      throw new GateError("REQUEST_SEMANTICS", `${op} cannot carry body or amount metadata`);
    }
    return { op, path, method: op.startsWith("sftp.list") ? "LIST" : "GET", bytes: 0, labels: [...(request.labels ?? [])] };
  }

  const canonical = canonicalBody(request.body);
  const body = canonical.body;
  const expectedKind = op === "sftp.put.canary" ? "canary" : "production";
  if (body.kind !== expectedKind) {
    throw new GateError("REQUEST_SEMANTICS", `${op} requires body kind '${expectedKind}'`);
  }
  const amount = finiteAmount(body.amount);
  const labels = [...(request.labels ?? [])];
  if (request.amount !== undefined && request.amount !== amount) {
    throw new GateError("REQUEST_SEMANTICS", "claimed amount does not match settlement body");
  }
  if (op === "sftp.put.canary") assertCanarySemantics(link, body, amount, labels);
  return {
    op,
    path,
    method: "PUT",
    body,
    amount,
    bytes: canonical.bytes,
    labels,
  };
}

/**
 * Produces the single representation consumed by both authorization and dispatch.
 * Caller-provided labels never decide what operation the body/path will execute.
 */
export function normalizeTransportRequest(link: Link, request: TransportRequest): TransportRequest {
  return link.kind === "rest" ? normalizeRest(link, request) : normalizeSftp(link, request);
}
