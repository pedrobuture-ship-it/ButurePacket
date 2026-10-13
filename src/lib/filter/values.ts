import type { FieldDef, FieldKind } from "./fields";
import { TCP_FLAGS } from "./fields";
import { FilterError } from "./lexer";

export type CidrValue = { family: 4 | 6; base: bigint; bits: number };

export type Value =
  | { kind: "string"; text: string }
  | { kind: "number"; n: number }
  | { kind: "ip"; cidr: CidrValue; text: string };

const SIZE_UNITS: Record<string, number> = { b: 1, k: 1024, kb: 1024, kib: 1024, m: 1024 ** 2, mb: 1024 ** 2, mib: 1024 ** 2, g: 1024 ** 3, gb: 1024 ** 3, gib: 1024 ** 3, t: 1024 ** 4, tb: 1024 ** 4 };
const TIME_UNITS: Record<string, number> = { us: 1, "µs": 1, ms: 1000, s: 1e6, m: 6e7, min: 6e7, h: 3.6e9 };
const NUMBER_WITH_UNIT = /^(\d+(?:\.\d+)?)([a-zA-Zµ]*)$/;

export function parseIPv4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let v = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    v = (v << 8n) | BigInt(p);
  }
  return v;
}

export function parseIPv6(text: string): bigint | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || text.includes(":::")) return null;
  let head = text;
  let tail4: bigint | null = null;
  const lastColon = text.lastIndexOf(":");
  if (text.includes(".")) {
    tail4 = parseIPv4(text.slice(lastColon + 1));
    if (tail4 === null) return null;
    head = text.slice(0, lastColon + 1) + "0:0";
  }
  const halves = head.split("::");
  if (halves.length > 2) return null;
  const groups = (s: string) => (s === "" ? [] : s.split(":"));
  const [left, right] = [groups(halves[0]), halves.length === 2 ? groups(halves[1]) : []];
  if (halves.length === 1 ? left.length !== 8 : left.length + right.length > 7) return null;
  const all = halves.length === 1 ? left : [...left, ...new Array<string>(8 - left.length - right.length).fill("0"), ...right];
  let v = 0n;
  for (const g of all) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  if (tail4 !== null) v = (v & ~0xffffffffn) | tail4;
  return v;
}

export function parseAddress(text: string): { family: 4 | 6; value: bigint } | null {
  const v4 = parseIPv4(text);
  if (v4 !== null) return { family: 4, value: v4 };
  const v6 = text.includes(":") ? parseIPv6(text) : null;
  return v6 !== null ? { family: 6, value: v6 } : null;
}

export function parseCidr(text: string): CidrValue | null {
  const [addr, len, ...rest] = text.split("/");
  if (rest.length) return null;
  const a = parseAddress(addr);
  if (!a) return null;
  const max = a.family === 4 ? 32 : 128;
  let bits = max;
  if (len !== undefined) {
    if (!/^\d{1,3}$/.test(len) || Number(len) > max) return null;
    bits = Number(len);
  }
  const hostBits = BigInt(max - bits);
  return { family: a.family, base: (a.value >> hostBits) << hostBits, bits };
}

/** Parsed addresses by text. Captures repeat the same few addresses, and BigInt parsing is slow. */
const addressCache = new Map<string, { family: 4 | 6; value: bigint } | null>();
const ADDRESS_CACHE_MAX = 100_000;

function cachedAddress(text: string): { family: 4 | 6; value: bigint } | null {
  const hit = addressCache.get(text);
  if (hit !== undefined) return hit;
  const parsed = parseAddress(text);
  if (addressCache.size >= ADDRESS_CACHE_MAX) addressCache.clear();
  addressCache.set(text, parsed);
  return parsed;
}

export function cidrContains(c: CidrValue, address: string): boolean {
  const a = cachedAddress(address);
  if (!a || a.family !== c.family) return false;
  const hostBits = BigInt((c.family === 4 ? 32 : 128) - c.bits);
  return (a.value >> hostBits) << hostBits === c.base;
}

function numberWithUnit(word: string, kind: "size" | "duration" | "number" | "port", field: string, pos: number): number {
  const m = NUMBER_WITH_UNIT.exec(word);
  if (!m) throw new FilterError(`Expected a number for "${field}" but found "${word}" at position ${pos}.`, pos);
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  if (kind === "size") {
    if (unit === "") return n;
    const f = SIZE_UNITS[unit];
    if (f === undefined) throw new FilterError(`Unknown size unit "${m[2]}" at position ${pos}. Use B, KB, MB or GB.`, pos);
    return n * f;
  }
  if (kind === "duration") {
    if (unit === "") return n * 1000; // plain numbers are milliseconds
    const f = TIME_UNITS[unit];
    if (f === undefined) throw new FilterError(`Unknown time unit "${m[2]}" at position ${pos}. Use us, ms, s, m or h.`, pos);
    return n * f;
  }
  if (unit !== "") throw new FilterError(`"${field}" takes a plain number; unexpected unit "${m[2]}" at position ${pos}.`, pos);
  if (kind === "port" && (!Number.isInteger(n) || n > 65535)) throw new FilterError(`Port must be an integer between 0 and 65535 (position ${pos}).`, pos);
  return n;
}

/** Turns the right-hand side of a comparison into a typed value for `field`. */
export function parseValue(field: FieldDef, text: string, quoted: boolean, pos: number): Value {
  const kind: FieldKind = field.kind;
  switch (kind) {
    case "ip": {
      const cidr = parseCidr(text);
      if (!cidr) throw new FilterError(`"${text}" is not a valid IP address or CIDR range (position ${pos}).`, pos);
      return { kind: "ip", cidr, text };
    }
    case "port":
    case "number":
    case "size":
    case "duration":
      if (quoted) throw new FilterError(`Expected a number for "${field.name}" at position ${pos}.`, pos);
      return { kind: "number", n: numberWithUnit(text, kind, field.name, pos) };
    case "mac": {
      const t = text.toLowerCase();
      if (!/^[0-9a-f:-]+$/.test(t)) throw new FilterError(`"${text}" is not a valid MAC address (position ${pos}).`, pos);
      return { kind: "string", text: t.replaceAll("-", ":") };
    }
    case "flags": {
      const t = text.toLowerCase();
      if (!TCP_FLAGS.includes(t)) throw new FilterError(`Unknown TCP flag "${text}" at position ${pos}. Use ${TCP_FLAGS.join(", ")}.`, pos);
      return { kind: "string", text: t };
    }
    default:
      return { kind: "string", text: text.toLowerCase() };
  }
}
