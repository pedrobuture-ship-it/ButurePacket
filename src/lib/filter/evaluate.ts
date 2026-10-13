import type { Node } from "./parser";
import type { Operator } from "./fields";
import { type Value, cidrContains } from "./values";

export type FieldValue = undefined | string | number | readonly string[] | readonly number[];

/** What a filter is evaluated against: a packet, a flow, a DNS transaction or an event. */
export interface Subject {
  /** Values for a canonical field name; `undefined` when the subject doesn't have it. */
  get(field: string): FieldValue;
  /** Lower-case protocol names this subject belongs to. */
  protocols(): readonly string[];
}

function asList(v: FieldValue): readonly (string | number)[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v as string | number];
}

function compareNumber(a: number, op: Operator, b: number): boolean {
  switch (op) {
    case "=":
      return a === b;
    case "!=":
      return a !== b;
    case ">":
      return a > b;
    case ">=":
      return a >= b;
    case "<":
      return a < b;
    case "<=":
      return a <= b;
    default:
      return false;
  }
}

function compareText(a: string, op: Operator, b: string): boolean {
  const x = a.toLowerCase();
  switch (op) {
    case "=":
      return x === b;
    case "!=":
      return x !== b;
    case "contains":
      return x.includes(b);
    case "startswith":
      return x.startsWith(b);
    case "endswith":
      return x.endsWith(b);
    default:
      return false;
  }
}

function matchOne(actual: string | number, op: Operator, value: Value): boolean {
  switch (value.kind) {
    case "number":
      return typeof actual === "number" && compareNumber(actual, op, value.n);
    case "ip": {
      if (typeof actual !== "string") return false;
      return cidrContains(value.cidr, actual);
    }
    case "string":
      return compareText(String(actual), op, value.text);
  }
}

/** `!=` is true when *no* value matches (so `ip != x` excludes every packet that involves x). */
function evalCmp(actual: FieldValue, op: Operator, value: Value): boolean {
  const list = asList(actual);
  if (op === "!=") return list.every((a) => !matchOne(a, "=", value));
  return list.some((a) => matchOne(a, op, value));
}

export function evaluate(node: Node | null, subject: Subject): boolean {
  if (node === null) return true;
  switch (node.type) {
    case "and":
      return evaluate(node.left, subject) && evaluate(node.right, subject);
    case "or":
      return evaluate(node.left, subject) || evaluate(node.right, subject);
    case "not":
      return !evaluate(node.expr, subject);
    case "protocol":
      return subject.protocols().includes(node.name);
    case "cmp": {
      if (node.field.name === "protocol") {
        const wanted = node.value.kind === "string" ? node.value.text : "";
        const has = subject.protocols().includes(wanted);
        return node.op === "=" ? has : !has;
      }
      return evalCmp(subject.get(node.field.name), node.op, node.value);
    }
  }
}
