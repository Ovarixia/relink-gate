import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

export interface KeyPair {
  keyId: string;
  orgId: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

export function generateOrgKeys(orgId: string): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId: `${orgId}-ed25519`,
    orgId,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      sorted[key] = sortValue(obj[key]);
    }
    return sorted;
  }
  return value;
}

export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

export function signBytes(privateKeyPem: string, message: string): string {
  const key = createPrivateKey(privateKeyPem);
  return sign(null, Buffer.from(message, "utf8"), key).toString("base64");
}

export function verifyBytes(publicKeyPem: string, message: string, signatureB64: string): boolean {
  const key = createPublicKey(publicKeyPem);
  return verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureB64, "base64"));
}

export function signPayload<T>(
  payload: T,
  keys: KeyPair,
): { payload: T; alg: "Ed25519"; keyId: string; orgId: string; signature: string } {
  const message = canonicalJson(payload);
  return {
    payload,
    alg: "Ed25519",
    keyId: keys.keyId,
    orgId: keys.orgId,
    signature: signBytes(keys.privateKeyPem, message),
  };
}

export function verifyPayload<T>(
  envelope: { payload: T; signature: string },
  publicKeyPem: string,
): boolean {
  return verifyBytes(publicKeyPem, canonicalJson(envelope.payload), envelope.signature);
}

export const GENESIS_HASH = "0".repeat(64);

export function eventHash(seq: number, prevHash: string, rest: unknown): string {
  return sha256Hex(`${seq}|${prevHash}|${canonicalJson(rest)}`);
}
