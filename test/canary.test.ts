import assert from "node:assert/strict";
import { test } from "node:test";
import { FrozenClock } from "../src/clock.js";
import { evaluateCanary } from "../src/canary.js";
import { restRequirements } from "../src/gate.js";
import type { Link, TransportRequest } from "../src/types.js";

function restLink(): Link {
  return {
    id: "link-rest-payments",
    name: "REST",
    kind: "rest",
    supplierOrgId: "he",
    relyingOrgId: "nw",
    state: "canary",
    requirements: restRequirements(),
    rampStageIndex: 0,
  };
}

test("canary passes only with labeled traffic to the claimed sink", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const link = restLink();
  const good: TransportRequest = {
    op: "rest.payment.canary",
    path: "/v1/payments",
    amount: 1,
    labels: ["canary"],
    body: {
      kind: "canary",
      canaryId: "cny_test",
      amount: 1,
      destination: "northwind-canary-sink",
    },
  };
  const passed = evaluateCanary(link, good, true, clock);
  assert.equal(passed.passed, true);

  const wrongSink = evaluateCanary(
    link,
    { ...good, body: { ...good.body as object, destination: "customer-account" } },
    true,
    clock,
  );
  assert.equal(wrongSink.passed, false);
  assert.match(wrongSink.reason, /sink/);
});

test("downstream rejection fails the canary", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const req: TransportRequest = {
    op: "rest.payment.canary",
    path: "/v1/payments",
    amount: 1,
    labels: ["canary"],
    body: { kind: "canary", amount: 1, destination: "northwind-canary-sink" },
  };
  const receipt = evaluateCanary(restLink(), req, false, clock);
  assert.equal(receipt.passed, false);
});
