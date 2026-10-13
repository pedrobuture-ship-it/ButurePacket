import { describe, expect, it } from "vitest";
import { filterItems } from "./apply";
import { FlowSubject } from "./adapters";
import { parseFilter } from "./index";
import { makeFlow } from "@/features/flows/testFlow";

describe("filterItems", () => {
  const flows = [makeFlow({ id: 1, totalBytes: 10 }), makeFlow({ id: 2, totalBytes: 5_000_000 }), makeFlow({ id: 3, totalBytes: 20, protocol: "UDP", applicationProtocol: "DNS" })];
  const ast = (text: string) => {
    const r = parseFilter(text);
    if (!r.ok) throw r.error;
    return r.ast;
  };
  it("returns everything for a null filter", () => {
    expect(filterItems(flows, null, new FlowSubject())).toBe(flows);
    expect(filterItems(new Set(flows), null, new FlowSubject())).toHaveLength(3);
  });
  it("keeps matching items in order", () => {
    expect(filterItems(flows, ast("bytes > 1MB"), new FlowSubject()).map((f) => f.id)).toEqual([2]);
    expect(filterItems(flows, ast("dns || bytes > 1MB"), new FlowSubject()).map((f) => f.id)).toEqual([2, 3]);
    expect(filterItems(flows, ast("bytes > 1GB"), new FlowSubject())).toEqual([]);
  });
});
