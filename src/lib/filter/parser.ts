import { FilterError, lex, type Token } from "./lexer";
import { type FieldDef, type Operator, OPERATORS_BY_KIND, closestField, lookupField, normalizeProtocol } from "./fields";
import { type Value, parseValue } from "./values";

export type Node =
  | { type: "and" | "or"; left: Node; right: Node }
  | { type: "not"; expr: Node }
  | { type: "cmp"; field: FieldDef; op: Operator; value: Value; pos: number }
  | { type: "protocol"; name: string; pos: number };

export type ParseResult = { ok: true; ast: Node | null } | { ok: false; error: FilterError };

const MAX_DEPTH = 64;

class Parser {
  private i = 0;
  constructor(private readonly tokens: Token[]) {}

  private peek(): Token | undefined {
    return this.tokens[this.i];
  }

  private next(): Token | undefined {
    return this.tokens[this.i++];
  }

  parse(): Node {
    const node = this.or(0);
    const extra = this.peek();
    if (extra) throw new FilterError(`Unexpected token "${extra.text}" at position ${extra.pos}.`, extra.pos);
    return node;
  }

  private or(depth: number): Node {
    let left = this.and(depth);
    while (this.peek()?.type === "or") {
      this.next();
      left = { type: "or", left, right: this.and(depth) };
    }
    return left;
  }

  private and(depth: number): Node {
    let left = this.not(depth);
    while (this.peek()?.type === "and") {
      this.next();
      left = { type: "and", left, right: this.not(depth) };
    }
    return left;
  }

  private not(depth: number): Node {
    if (depth > MAX_DEPTH) throw new FilterError("Filter is nested too deeply.", this.peek()?.pos ?? 0);
    if (this.peek()?.type === "not") {
      this.next();
      return { type: "not", expr: this.not(depth + 1) };
    }
    return this.primary(depth);
  }

  private primary(depth: number): Node {
    const t = this.next();
    if (!t) throw new FilterError("Unexpected end of filter.", this.endPos());
    if (t.type === "lparen") {
      const inner = this.or(depth + 1);
      const close = this.next();
      if (!close || close.type !== "rparen") throw new FilterError(`Missing closing parenthesis for "(" at position ${t.pos}.`, t.pos);
      return inner;
    }
    if (t.type !== "word") throw new FilterError(`Unexpected token "${t.text}" at position ${t.pos}.`, t.pos);

    const field = lookupField(t.text);
    const nextIsOp = this.peek()?.type === "op";
    if (!(field && nextIsOp)) {
      // Not a comparison: a bare word is a protocol match, e.g. `tcp` or `dns`.
      const proto = nextIsOp ? null : normalizeProtocol(t.text);
      if (proto) return { type: "protocol", name: proto, pos: t.pos };
      if (field) throw new FilterError(`Field "${t.text}" needs an operator and a value (position ${t.pos}).`, t.pos);
      const hint = closestField(t.text);
      throw new FilterError(`Unknown field or protocol "${t.text}" at position ${t.pos}.${hint ? ` Did you mean "${hint}"?` : ""}`, t.pos);
    }

    const op = this.next()!;
    if (op.text === "!" || !["=", "!=", ">", ">=", "<", "<=", "contains", "startswith", "endswith"].includes(op.text)) throw new FilterError(`Unexpected token "${op.text}" at position ${op.pos}.`, op.pos);
    const operator = op.text as Operator;
    if (!OPERATORS_BY_KIND[field.kind].includes(operator)) {
      throw new FilterError(`Operator "${operator}" cannot be used with "${field.name}" at position ${op.pos}. Allowed: ${OPERATORS_BY_KIND[field.kind].join(", ")}.`, op.pos);
    }
    const v = this.next();
    if (!v) throw new FilterError(`Missing value after "${field.name} ${operator}" at position ${this.endPos()}.`, this.endPos());
    if (v.type !== "word" && v.type !== "string") throw new FilterError(`Unexpected token "${v.text}" at position ${v.pos}.`, v.pos);
    return { type: "cmp", field, op: operator, value: parseValue(field, v.text, v.type === "string", v.pos), pos: t.pos };
  }

  private endPos(): number {
    const last = this.tokens[this.tokens.length - 1];
    return last ? last.end : 0;
  }
}

/** Parses a filter. An empty filter yields `ast: null` (matches everything). */
export function parseFilter(input: string): ParseResult {
  const { tokens, error } = lex(input);
  if (error) return { ok: false, error };
  if (tokens.length === 0) return { ok: true, ast: null };
  try {
    return { ok: true, ast: new Parser(tokens).parse() };
  } catch (e) {
    if (e instanceof FilterError) return { ok: false, error: e };
    throw e;
  }
}
