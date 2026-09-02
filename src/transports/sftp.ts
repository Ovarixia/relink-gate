import type { TransportRequest, TransportResponse } from "../types.js";

/**
 * Virtual SFTP inbox. PUT/GET/LIST only — no real SSH daemon.
 */
export class SftpInbox {
  readonly files = new Map<string, { bytes: number; body: unknown; putAt: string }>();

  handle(req: TransportRequest): TransportResponse {
    if (req.op.startsWith("sftp.list")) {
      return {
        ok: true,
        status: 200,
        body: { files: [...this.files.keys()] },
      };
    }
    if (req.op.startsWith("sftp.get")) {
      const file = this.files.get(req.path);
      if (!file) {
        return { ok: false, status: 404, body: { error: "no such file" } };
      }
      return { ok: true, status: 200, body: file };
    }
    if (req.op.startsWith("sftp.put")) {
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
}
