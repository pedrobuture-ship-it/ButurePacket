export type TokenType = "lparen" | "rparen" | "and" | "or" | "not" | "op" | "string" | "word";

export interface Token {
  type: TokenType;
  /** Source text of the token (for strings: the unquoted content). */
  text: string;
  /** Zero-based character offset of the token start. */
  pos: number;
  /** Offset just past the token. */
  end: number;
}

export class FilterError extends Error {
  constructor(
    message: string,
    public readonly position: number,
  ) {
    super(message);
    this.name = "FilterError";
  }
}

const OPERATOR_CHARS = new Set(["=", "!", "<", ">", "&", "|"]);
const VALID_SYMBOLS = new Set(["=", "==", "!=", ">", ">=", "<", "<=", "&&", "||", "!"]);
const KEYWORDS: Record<string, TokenType> = { and: "and", or: "or", not: "not", contains: "op", startswith: "op", endswith: "op" };

export interface LexResult {
  tokens: Token[];
  /** Set when lexing stopped early; `tokens` holds everything before the problem. */
  error?: FilterError;
}

/** Splits a filter into tokens. Never evals or interprets anything; errors carry the offending position. */
export function lex(input: string): LexResult {
  const tokens: Token[] = [];
  let i = 0;
  const fail = (message: string, position: number): LexResult => ({ tokens, error: new FilterError(message, position) });
  while (i < input.length) {
    const c = input[i];
    if (/\s/.test(c)) {
      i++;
    } else if (c === "(" || c === ")") {
      tokens.push({ type: c === "(" ? "lparen" : "rparen", text: c, pos: i, end: i + 1 });
      i++;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      let out = "";
      let closed = false;
      while (j < input.length) {
        if (input[j] === "\\" && j + 1 < input.length) {
          out += input[j + 1];
          j += 2;
        } else if (input[j] === c) {
          closed = true;
          j++;
          break;
        } else {
          out += input[j++];
        }
      }
      if (!closed) return fail(`Unterminated string starting at position ${i}.`, i);
      tokens.push({ type: "string", text: out, pos: i, end: j });
      i = j;
    } else if (OPERATOR_CHARS.has(c)) {
      let j = i;
      while (j < input.length && OPERATOR_CHARS.has(input[j])) j++;
      const sym = input.slice(i, j);
      if (/^!{2,}$/.test(sym)) {
        // Stacked negations: `!!tcp`
        for (let k = 0; k < sym.length; k++) tokens.push({ type: "not", text: "!", pos: i + k, end: i + k + 1 });
        i = j;
        continue;
      }
      if (!VALID_SYMBOLS.has(sym)) return fail(`Unexpected token "${sym}" at position ${i}.`, i);
      const type: TokenType = sym === "&&" ? "and" : sym === "||" ? "or" : sym === "!" ? "not" : "op";
      tokens.push({ type, text: sym === "==" ? "=" : sym, pos: i, end: j });
      i = j;
    } else {
      let j = i;
      while (j < input.length && !/\s/.test(input[j]) && !"()\"'".includes(input[j]) && !OPERATOR_CHARS.has(input[j])) j++;
      const word = input.slice(i, j);
      const kw = KEYWORDS[word.toLowerCase()];
      tokens.push({ type: kw ?? "word", text: kw ? word.toLowerCase() : word, pos: i, end: j });
      i = j;
    }
  }
  return { tokens };
}
