import type { Link, LinkState } from "./types.js";
import { GateError } from "./types.js";

const ALLOWED: Record<LinkState, readonly LinkState[]> = {
  cut: ["claim", "revoked"],
  claim: ["quarantine", "canary", "cut", "revoked"],
  quarantine: ["canary", "revoked", "cut"],
  canary: ["ramp", "revoked", "quarantine"],
  ramp: ["revoked", "cut"],
  revoked: ["claim", "cut"],
};

export function assertTransition(from: LinkState, to: LinkState): void {
  if (!ALLOWED[from].includes(to)) {
    throw new GateError("ILLEGAL_TRANSITION", `Cannot transition ${from} → ${to}`);
  }
}

export function transition(link: Link, to: LinkState): { from: LinkState; to: LinkState } {
  const from = link.state;
  assertTransition(from, to);
  link.state = to;
  if (to === "cut" || to === "revoked") {
    link.rampStageIndex = 0;
  }
  return { from, to };
}

export function isLive(state: LinkState): boolean {
  return state === "quarantine" || state === "canary" || state === "ramp";
}
