import { describe, expect, it } from "vitest";
import { Interner, ListInterner } from "./intern";

describe("Interner", () => {
  it("returns the same string instance for equal values", () => {
    const i = new Interner();
    const a = i.intern("192.168." + "1.20");
    const b = i.intern("192.168.1." + "20");
    expect(a).toBe(b);
    expect(i.size).toBe(1);
  });
  it("passes null/undefined through and stops growing at the cap", () => {
    const i = new Interner(2);
    expect(i.intern(null)).toBeNull();
    expect(i.intern(undefined)).toBeUndefined();
    i.intern("a");
    i.intern("b");
    expect(i.intern("c")).toBe("c");
    expect(i.size).toBe(2);
    i.clear();
    expect(i.size).toBe(0);
  });
});

describe("ListInterner", () => {
  it("shares equal lists", () => {
    const l = new ListInterner();
    const a = l.intern(["SYN", "ACK"]);
    expect(l.intern(["SYN", "ACK"])).toBe(a);
    expect(l.intern(["ACK"])).not.toBe(a);
    expect(l.intern(null)).toBeNull();
  });
});
