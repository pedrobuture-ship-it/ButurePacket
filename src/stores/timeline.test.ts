import { beforeEach, describe, expect, it } from "vitest";
import { ALL_GROUPS, useTimelineStore } from "./timeline";

const s = () => useTimelineStore.getState();

describe("timeline store", () => {
  beforeEach(() => s().resetFilters());

  it("starts with every lane enabled and an automatic window", () => {
    expect([...s().groups].sort()).toEqual([...ALL_GROUPS].sort());
    expect(s().window).toBeNull();
  });
  it("toggles lanes without mutating the previous set", () => {
    const before = s().groups;
    s().toggleGroup("dns");
    expect(s().groups.has("dns")).toBe(false);
    expect(before.has("dns")).toBe(true);
    s().toggleGroup("dns");
    expect(s().groups.has("dns")).toBe(true);
  });
  it("reset restores everything", () => {
    s().toggleGroup("tls");
    s().setText("github");
    s().setFlow(4);
    s().setWindow({ start: 1, end: 2 });
    s().selectEvent(9);
    s().resetFilters();
    expect(s()).toMatchObject({ text: "", flowId: null, window: null });
    expect(s().groups.size).toBe(ALL_GROUPS.length);
  });
});
