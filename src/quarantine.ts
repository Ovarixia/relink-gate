import type { Clock, Link, QuarantineSpec, RampStage, TransportRequest, TransportResponse } from "./types.js";
import { GateError } from "./types.js";
import { isLive } from "./machine.js";

export interface RateWindow {
  startedAtMs: number;
  count: number;
  bytes: number;
}

export class AccessProxy {
  private readonly windows = new Map<string, RateWindow>();

  constructor(private readonly clock: Clock) {}

  authorize(
    link: Link,
    req: TransportRequest,
    stage: RampStage | undefined,
  ): { ok: true; spec: QuarantineSpec | RampStage } | { ok: false; reason: string } {
    if (!isLive(link.state)) {
      return { ok: false, reason: `link is ${link.state}; proxy refuses traffic` };
    }

    if (link.state === "quarantine" || link.state === "canary") {
      return this.checkQuarantine(link, req);
    }

    const active = stage ?? link.requirements.ramp.stages[link.rampStageIndex];
    if (!active) {
      return { ok: false, reason: "no ramp stage configured" };
    }
    return this.checkRamp(link, req, active);
  }

  enforce(link: Link, req: TransportRequest, stage?: RampStage): void {
    const decision = this.authorize(link, req, stage);
    if (!decision.ok) {
      throw new GateError("PROXY_DENIED", decision.reason);
    }
  }

  record(linkId: string, bytes: number): void {
    const now = this.clock.now().getTime();
    const window = this.windows.get(linkId);
    if (!window) {
      this.windows.set(linkId, { startedAtMs: now, count: 1, bytes });
      return;
    }
    window.count += 1;
    window.bytes += bytes;
  }

  reset(linkId: string): void {
    this.windows.delete(linkId);
  }

  private checkQuarantine(
    link: Link,
    req: TransportRequest,
  ): { ok: true; spec: QuarantineSpec } | { ok: false; reason: string } {
    const spec = link.requirements.quarantine;
    if (!spec.allowedOps.includes(req.op) && !spec.allowedOps.includes("*")) {
      return { ok: false, reason: `op '${req.op}' not allowed in quarantine` };
    }
    if (!this.withinWindow(link.id, spec.windowMs, spec.maxRequestsPerWindow, spec.maxBytes, req.bytes ?? 0)) {
      return { ok: false, reason: "quarantine rate / size handbrake" };
    }
    return { ok: true, spec };
  }

  private checkRamp(
    link: Link,
    req: TransportRequest,
    stage: RampStage,
  ): { ok: true; spec: RampStage } | { ok: false; reason: string } {
    if (!stage.allowedOps.includes(req.op) && !stage.allowedOps.includes("*")) {
      return { ok: false, reason: `op '${req.op}' not allowed at ramp stage ${stage.name}` };
    }
    if (req.amount !== undefined && req.amount > stage.maxAmount) {
      return { ok: false, reason: `amount ${req.amount} exceeds stage cap ${stage.maxAmount}` };
    }
    const q = link.requirements.quarantine;
    if (!this.withinWindow(link.id, q.windowMs, stage.throughputPerWindow, q.maxBytes * 8, req.bytes ?? 0)) {
      return { ok: false, reason: `throughput handbrake at stage ${stage.name}` };
    }
    return { ok: true, spec: stage };
  }

  private withinWindow(
    linkId: string,
    windowMs: number,
    maxCount: number,
    maxBytes: number,
    extraBytes: number,
  ): boolean {
    const now = this.clock.now().getTime();
    let window = this.windows.get(linkId);
    if (!window || now - window.startedAtMs >= windowMs) {
      window = { startedAtMs: now, count: 0, bytes: 0 };
      this.windows.set(linkId, window);
    }
    return window.count < maxCount && window.bytes + extraBytes <= maxBytes;
  }
}

export function deniedResponse(reason: string): TransportResponse {
  return { ok: false, status: 403, body: { error: reason }, deniedReason: reason };
}
