import { FIELDS, OPERATORS_BY_KIND, PROTOCOLS, TCP_FLAGS, lookupField, type FieldDef } from "./fields";
import { lex, type Token } from "./lexer";

export interface Recents {
  ips: readonly string[];
  domains: readonly string[];
}

export interface Suggestion {
  /** Text shown in the list. */
  label: string;
  /** Text that replaces the word being typed. */
  insert: string;
  kind: "field" | "operator" | "protocol" | "value" | "keyword";
  hint?: string;
}

export interface Suggestions {
  /** Range of the input to replace when a suggestion is accepted. */
  from: number;
  to: number;
  items: Suggestion[];
}

const MAX_ITEMS = 8;
const POPULAR = ["tcp", "udp", "dns", "tls", "ip", "dst.port", "domain", "latency"];
const LOGIC = [
  { label: "&&", insert: "&& ", kind: "keyword" as const, hint: "and" },
  { label: "||", insert: "|| ", kind: "keyword" as const, hint: "or" },
];

function rank(items: Suggestion[], prefix: string): Suggestion[] {
  const p = prefix.toLowerCase();
  if (!p) return items.slice(0, MAX_ITEMS);
  const starts = items.filter((i) => i.insert.toLowerCase().startsWith(p));
  const contains = items.filter((i) => !i.insert.toLowerCase().startsWith(p) && i.insert.toLowerCase().includes(p));
  return [...starts, ...contains].filter((i) => i.insert.toLowerCase() !== p).slice(0, MAX_ITEMS);
}

function valueSuggestions(field: FieldDef, recents: Recents): Suggestion[] {
  switch (field.kind) {
    case "protocol":
      return PROTOCOLS.map((p) => ({ label: p, insert: p, kind: "protocol" as const }));
    case "flags":
      return TCP_FLAGS.map((f) => ({ label: f, insert: f, kind: "value" as const }));
    case "ip":
      return recents.ips.map((ip) => ({ label: ip, insert: ip, kind: "value" as const, hint: "recent" }));
    case "string":
      return field.name === "domain" || field.name === "sni" ? recents.domains.map((d) => ({ label: d, insert: d.includes(" ") ? `"${d}"` : d, kind: "value" as const, hint: "recent" })) : [];
    case "duration":
      return ["10ms", "50ms", "100ms", "1s"].map((v) => ({ label: v, insert: v, kind: "value" as const }));
    case "size":
      return ["1KB", "100KB", "1MB", "10MB"].map((v) => ({ label: v, insert: v, kind: "value" as const }));
    default:
      return [];
  }
}

/**
 * What to offer at `cursor`: field names and protocols where a condition may start, operators after
 * a field, and values (protocols, recent IPs/domains, flags, units) after an operator.
 */
export function suggest(text: string, cursor: number, recents: Recents): Suggestions {
  const { tokens } = lex(text.slice(0, cursor));
  const last: Token | undefined = tokens[tokens.length - 1];
  // A word touching the cursor is the thing being completed.
  const typing = last && last.type !== "string" && last.end === cursor && (last.type === "word" || last.type === "op" || last.type === "and" || last.type === "or" || last.type === "not") && /\w/.test(last.text);
  const editing = typing ? last : undefined;
  const before = editing ? tokens.slice(0, -1) : tokens;
  const prev = before[before.length - 1];
  const prefix = editing?.text ?? "";
  const range = { from: editing ? editing.pos : cursor, to: cursor };

  // after `field op` → values
  const prev2 = before[before.length - 2];
  if (prev?.type === "op" && prev2?.type === "word") {
    const field = lookupField(prev2.text);
    return { ...range, items: field ? rank(valueSuggestions(field, recents), prefix) : [] };
  }
  // after `field` → operators
  if (prev?.type === "word") {
    const field = lookupField(prev.text);
    if (field) {
      const ops = OPERATORS_BY_KIND[field.kind].map((op) => ({ label: op, insert: op === "contains" || op === "startswith" || op === "endswith" ? `${op} ` : `${op} `, kind: "operator" as const }));
      return { ...range, items: rank(ops, prefix) };
    }
    // after a bare protocol → logical operators
    return { ...range, items: rank(LOGIC, prefix) };
  }
  // after a finished condition (value, string or ")") → logical operators
  if (prev && (prev.type === "string" || prev.type === "rparen")) {
    return { ...range, items: rank(LOGIC, prefix) };
  }
  // start, after `&&`/`||`/`!`/`(` → a field or a protocol
  const all: Suggestion[] = [
    ...FIELDS.map((f) => ({ label: f.name, insert: f.name, kind: "field" as const, hint: f.description })),
    ...PROTOCOLS.map((p) => ({ label: p, insert: p, kind: "protocol" as const })),
  ];
  // With nothing typed yet, lead with the conditions people reach for most.
  const rankOf = (i: Suggestion) => (POPULAR.indexOf(i.label) === -1 ? POPULAR.length : POPULAR.indexOf(i.label));
  const starters = [...all].sort((a, b) => rankOf(a) - rankOf(b));
  return { ...range, items: rank(starters, prefix) };
}

/** Applies a suggestion to the input; returns the new text and cursor. */
export function applySuggestion(text: string, s: Suggestions, item: Suggestion): { text: string; cursor: number } {
  const next = text.slice(0, s.from) + item.insert + text.slice(s.to);
  return { text: next, cursor: s.from + item.insert.length };
}
