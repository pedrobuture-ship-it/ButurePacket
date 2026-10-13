import { describe, expect, it } from "vitest";
import { fuzzyScore, rankBy } from "./fuzzy";

describe("fuzzyScore", () => {
  it("requires all characters in order", () => {
    expect(fuzzyScore("gtf", "Go to Flows")).not.toBeNull();
    expect(fuzzyScore("fgt", "Go to Flows")).toBeNull();
    expect(fuzzyScore("xyz", "Go to Flows")).toBeNull();
  });
  it("matches everything for an empty query", () => expect(fuzzyScore("  ", "anything")).toBe(0));
  it("is case-insensitive and prefers substrings and word starts", () => {
    expect(fuzzyScore("FLOWS", "go to flows")).toBeGreaterThan(fuzzyScore("flows", "f l o w s extra")!);
    expect(fuzzyScore("pc", "Open PCAP")!).toBeGreaterThan(fuzzyScore("pc", "Capture Permission check")! - 100);
  });
});

describe("rankBy", () => {
  const items = ["Start Capture", "Stop", "Pause", "Open PCAP", "Go to Packets", "Go to Flows", "Clear Filters"];
  it("keeps order for an empty query", () => expect(rankBy(items, "", (s) => s)).toEqual(items));
  it("ranks the best match first and drops non-matches", () => {
    expect(rankBy(items, "flows", (s) => s)[0]).toBe("Go to Flows");
    expect(rankBy(items, "open", (s) => s)[0]).toBe("Open PCAP");
    expect(rankBy(items, "zzz", (s) => s)).toEqual([]);
    expect(rankBy(items, "cf", (s) => s)).toContain("Clear Filters");
  });
  it("is stable for equal scores", () => {
    expect(rankBy(["aa", "ab", "ac"], "a", (s) => s)).toEqual(["aa", "ab", "ac"]);
  });
});
