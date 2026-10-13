import { describe, expect, it } from "vitest";
import { clamp, loadSize } from "./layout";

describe("layout helpers", () => {
  it("clamps into range", () => {
    expect(clamp(5, 10, 20)).toBe(10);
    expect(clamp(25, 10, 20)).toBe(20);
    expect(clamp(15, 10, 20)).toBe(15);
  });
  it("falls back when storage is unavailable", () => {
    expect(loadSize("x", 123)).toBe(123);
  });
});
