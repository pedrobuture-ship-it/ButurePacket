import { describe, expect, it } from "vitest";
import { formatOffset, hexByte, inRange, rowOfOffset } from "./hex";

describe("hex helpers", () => {
  it("pads offsets and bytes", () => {
    expect(formatOffset(0x10)).toBe("00000010");
    expect(hexByte(5)).toBe("05");
    expect(hexByte(255)).toBe("ff");
  });
  it("checks range membership", () => {
    const r = { offset: 12, length: 4 };
    expect([11, 12, 15, 16].map((i) => inRange(i, r))).toEqual([false, true, true, false]);
    expect(inRange(3, null)).toBe(false);
    expect(inRange(3, { offset: 3, length: 0 })).toBe(false);
  });
  it("maps offsets to rows", () => {
    expect(rowOfOffset(0)).toBe(0);
    expect(rowOfOffset(31)).toBe(1);
    expect(rowOfOffset(32)).toBe(2);
  });
});
