import assert from "node:assert/strict";
import { test } from "node:test";
import { assertTransition, transition } from "../src/machine.js";
import type { Link } from "../src/types.js";
import { GateError } from "../src/types.js";
import { restRequirements } from "../src/gate.js";

function link(state: Link["state"]): Link {
  return {
    id: "l1",
    name: "t",
    kind: "rest",
    supplierOrgId: "s",
    relyingOrgId: "r",
    state,
    requirements: restRequirements(),
    rampStageIndex: 2,
  };
}

test("legal path cut → claim → quarantine → canary → ramp", () => {
  const l = link("cut");
  assert.equal(transition(l, "claim").to, "claim");
  assert.equal(transition(l, "quarantine").to, "quarantine");
  assert.equal(transition(l, "canary").to, "canary");
  assert.equal(transition(l, "ramp").to, "ramp");
});

test("ramp rolls back to revoked and resets stage index", () => {
  const l = link("ramp");
  transition(l, "revoked");
  assert.equal(l.state, "revoked");
  assert.equal(l.rampStageIndex, 0);
});

test("illegal transitions throw", () => {
  assert.throws(() => assertTransition("cut", "ramp"), GateError);
  assert.throws(() => assertTransition("ramp", "canary"), GateError);
  assert.throws(() => assertTransition("quarantine", "claim"), GateError);
});

test("revoked can re-enter via a new claim", () => {
  const l = link("revoked");
  transition(l, "claim");
  assert.equal(l.state, "claim");
});
