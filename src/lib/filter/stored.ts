import type { StoredPacketQuery } from "@/types/ipc";
import type { Node } from "./parser";

export type StoredQueryResult = { ok: true; query: StoredPacketQuery } | { ok: false; reason: string };

/**
 * Translates a filter into a search of the stored capture. Only conditions that map onto an indexed
 * column and are joined with `&&` can be searched there; anything else says why it can't.
 */
export function toStoredQuery(ast: Node | null): StoredQueryResult {
  const query: StoredPacketQuery = {};
  if (ast === null) return { ok: true, query };
  const fail = (reason: string): StoredQueryResult => ({ ok: false, reason });
  const set = <K extends keyof StoredPacketQuery>(key: K, value: StoredPacketQuery[K]): string | null => {
    if (query[key] !== undefined) return `"${key}" is used more than once`;
    query[key] = value;
    return null;
  };

  const visit = (n: Node): string | null => {
    switch (n.type) {
      case "and":
        return visit(n.left) ?? visit(n.right);
      case "or":
        return "'||' cannot be searched in the stored capture";
      case "not":
        return "'!' cannot be searched in the stored capture";
      case "protocol":
        return set("protocol", n.name);
      case "cmp": {
        const { field, op, value } = n;
        if (op !== "=") return `'${op}' on ${field.name} cannot be searched in the stored capture`;
        switch (field.name) {
          case "ip":
          case "src.ip":
          case "dst.ip": {
            if (value.kind !== "ip") return null;
            const max = value.cidr.family === 4 ? 32 : 128;
            if (value.cidr.bits !== max) return "address ranges (CIDR) cannot be searched in the stored capture";
            const key = field.name === "ip" ? "ip" : field.name === "src.ip" ? "srcIp" : "dstIp";
            return set(key, value.text.split("/")[0]);
          }
          case "flow":
            return value.kind === "number" ? set("flowId", value.n) : null;
          case "domain":
            return value.kind === "string" ? set("domain", value.text) : null;
          case "protocol":
            return value.kind === "string" ? set("protocol", value.text) : null;
          default:
            return `"${field.name}" is not indexed in the stored capture`;
        }
      }
    }
  };
  const problem = visit(ast);
  return problem ? fail(problem) : { ok: true, query };
}
