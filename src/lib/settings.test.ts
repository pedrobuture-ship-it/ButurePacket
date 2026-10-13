import { describe, expect, it } from "vitest";
import { resetLayout } from "./settings";

function fakeStorage(init: Record<string, string>) {
  const data = new Map(Object.entries(init));
  return {
    get length() {
      return data.size;
    },
    key: (i: number) => [...data.keys()][i] ?? null,
    removeItem: (k: string) => void data.delete(k),
    keys: () => [...data.keys()],
  };
}

describe("resetLayout", () => {
  it("removes only layout keys", () => {
    const s = fakeStorage({ "buturepacket.layout.packet-inspector": "500", "buturepacket.layout.flow-inspector": "440", "buturepacket.sidebarCollapsed": "1", "buturepacket.persistCaptures": "0", other: "x" });
    expect(resetLayout(s)).toBe(3);
    expect(s.keys().sort()).toEqual(["buturepacket.persistCaptures", "other"]);
  });
  it("is a no-op on empty storage", () => expect(resetLayout(fakeStorage({}))).toBe(0));
});
