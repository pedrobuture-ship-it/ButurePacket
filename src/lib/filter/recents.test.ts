import { describe, expect, it } from "vitest";
import { buildRecents, newestDistinct } from "./recents";

describe("recents", () => {
  it("returns distinct values newest first and skips empties", () => {
    expect(newestDistinct(["a", "b", null, "a", "c", undefined, ""])).toEqual(["c", "a", "b"]);
  });
  it("caps the list", () => {
    expect(newestDistinct(Array.from({ length: 100 }, (_, i) => String(i)), 5)).toEqual(["99", "98", "97", "96", "95"]);
  });
  it("builds both lists", () => {
    expect(buildRecents({ ipsOldestFirst: ["1.1.1.1", "2.2.2.2"], domainsOldestFirst: ["x.com"] })).toEqual({ ips: ["2.2.2.2", "1.1.1.1"], domains: ["x.com"] });
  });
});
