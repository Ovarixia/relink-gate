import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Clock, PolicyCondition, PolicyDecision, PolicyDocument } from "./types.js";
import { iso } from "./clock.js";

export interface PolicyFacts {
  claim: {
    fresh: boolean;
    revoked: boolean;
    expired: boolean;
    issuerOrgId: string;
    audienceOrgId: string;
    linkId: string;
    assertions: Record<string, boolean | string | number>;
    challengeBound: boolean;
  };
  challenge: {
    satisfied: boolean;
    nonceMatch: boolean;
    expired: boolean;
  };
  link: {
    kind: string;
    state: string;
    neverSkipQuarantine: boolean;
    requiredAssertionsMet: boolean;
  };
}

function getPath(facts: PolicyFacts, path: string): unknown {
  const parts = path.split(".");
  let cur: unknown = facts;
  for (const part of parts) {
    if (cur === null || cur === undefined || typeof cur !== "object") {
      return undefined;
    }
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function matches(condition: PolicyCondition, facts: PolicyFacts): boolean {
  const left = getPath(facts, condition.path);
  switch (condition.op) {
    case "truthy":
      return Boolean(left);
    case "falsy":
      return !left;
    case "eq":
      return left === condition.value;
    case "neq":
      return left !== condition.value;
    case "gt":
      return typeof left === "number" && typeof condition.value === "number" && left > condition.value;
    case "gte":
      return typeof left === "number" && typeof condition.value === "number" && left >= condition.value;
    case "lt":
      return typeof left === "number" && typeof condition.value === "number" && left < condition.value;
    case "lte":
      return typeof left === "number" && typeof condition.value === "number" && left <= condition.value;
    case "in":
      return Array.isArray(condition.value) && condition.value.includes(left);
    default:
      return false;
  }
}

function ruleMatches(rule: PolicyDocument["rules"][number], facts: PolicyFacts): boolean {
  const allOk = (rule.when.all ?? []).every((c) => matches(c, facts));
  const anyList = rule.when.any;
  const anyOk = !anyList || anyList.length === 0 || anyList.some((c) => matches(c, facts));
  return allOk && anyOk;
}

/** First matching rule wins. Deterministic: rule order is the priority. */
export function evaluatePolicy(policy: PolicyDocument, facts: PolicyFacts, clock: Clock): PolicyDecision {
  for (const rule of policy.rules) {
    if (ruleMatches(rule, facts)) {
      return {
        effect: rule.effect,
        ruleId: rule.id,
        reason: rule.reason,
        evaluatedAt: iso(clock),
      };
    }
  }
  return {
    effect: policy.defaultEffect,
    ruleId: `${policy.id}:default`,
    reason: `No rule matched; default ${policy.defaultEffect}`,
    evaluatedAt: iso(clock),
  };
}

export function loadPolicyFile(filename: string): PolicyDocument {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "..", "policies", filename),
    join(process.cwd(), "policies", filename),
  ];
  for (const path of candidates) {
    try {
      return JSON.parse(readFileSync(path, "utf8")) as PolicyDocument;
    } catch {
      // try next
    }
  }
  throw new Error(`Policy file not found: ${filename}`);
}

