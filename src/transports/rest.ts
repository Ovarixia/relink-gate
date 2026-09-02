import type { TransportRequest, TransportResponse } from "../types.js";

/**
 * In-process REST sink for the relying party.
 * Simulates a payment ingest API — not a bank core.
 */
export class RestPaymentSink {
  readonly received: TransportRequest[] = [];

  handle(req: TransportRequest): TransportResponse {
    this.received.push(req);
    if (req.path !== "/v1/payments" && req.path !== "/v1/health") {
      return { ok: false, status: 404, body: { error: "unknown route" } };
    }
    if (req.path === "/v1/health") {
      return { ok: true, status: 200, body: { status: "ok" } };
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    return {
      ok: true,
      status: 201,
      body: {
        accepted: true,
        transport: "rest",
        reference: body.reference,
        destination: body.destination,
        amount: body.amount,
      },
    };
  }
}
