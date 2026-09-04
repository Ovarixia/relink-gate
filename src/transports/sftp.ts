import type { TransportRequest, TransportResponse } from "../types.js";

/**
 * Virtual SFTP inbox. PUT/GET/LIST only — no real SSH daemon.
 */
export class SftpInbox {
  readonly files = new Map<string, { bytes: number; body: unknown; putAt: string }>();

  projectedResponseBytes(req: TransportRequest): number {
    let body: unknown = {};
    let declaredFileBytes = 0;
    if (req.op === "sftp.list" || req.op === "sftp.list.quarantine") {
      body = { files: this.list(req.path) };
    } else if (req.op === "sftp.get") {
      const file = this.files.get(req.path);
      body = file ?? { error: "no such file" };
      if (file) {
        if (!Number.isSafeInteger(file.bytes) || file.bytes < 0) return Number.POSITIVE_INFINITY;
        declaredFileBytes = file.bytes;
      }
    }
    try {
      return Math.max(declaredFileBytes, Buffer.byteLength(JSON.stringify(body), "utf8"));
    } catch {
      return Number.POSITIVE_INFINITY;
    }
  }

  handle(req: TransportRequest): TransportResponse {
    if (req.op === "sftp.list" || req.op === "sftp.list.quarantine") {
      return {
        ok: true,
        status: 200,
        body: { files: this.list(req.path) },
      };
    }
    if (req.op === "sftp.get") {
      const file = this.files.get(req.path);
      if (!file) {
        return { ok: false, status: 404, body: { error: "no such file" } };
      }
      return { ok: true, status: 200, body: file };
    }
    if (req.op === "sftp.put.canary" || req.op === "sftp.put.settlement") {
      this.files.set(req.path, {
        bytes: req.bytes ?? 0,
        body: req.body,
        putAt: new Date().toISOString(),
      });
      return {
        ok: true,
        status: 201,
        body: { stored: req.path, transport: "sftp" },
      };
    }
    return { ok: false, status: 400, body: { error: `unsupported sftp op ${req.op}` } };
  }

  private list(path: string): string[] {
    const prefix = path.endsWith("/") ? path : `${path}/`;
    return [...this.files.keys()].filter((file) => file.startsWith(prefix));
  }
}
