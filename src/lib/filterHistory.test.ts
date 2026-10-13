import { describe, expect, it } from "vitest";
import { loadHistory, pushHistory } from "./filterHistory";

describe("filter history", () => {
  it("puts the newest first without duplicates and stays bounded", () => {
    expect(pushHistory(["a", "b"], "b")).toEqual(["b", "a"]);
    expect(pushHistory(["a"], "  ")).toEqual(["a"]);
    expect(pushHistory(Array.from({ length: 12 }, (_, i) => `f${i}`), "new")).toHaveLength(12);
  });
  it("survives corrupt storage", () => {
    expect(loadHistory({ getItem: () => "{nope" })).toEqual([]);
    expect(loadHistory({ getItem: () => '[1,"x"]' })).toEqual(["x"]);
  });
});
