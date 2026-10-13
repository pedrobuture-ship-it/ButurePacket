import { describe, expect, it } from "vitest";
import { sparklinePath } from "./Sparkline";

describe("sparklinePath", () => {
  it("is empty for fewer than two points", () => expect(sparklinePath([5], 100, 20)).toBe(""));
  it("scales the maximum to the top and zero to the bottom", () => {
    expect(sparklinePath([0, 10], 100, 20)).toBe("M0.0,19.0 L100.0,1.0");
  });
  it("handles all-zero data without NaN", () => expect(sparklinePath([0, 0, 0], 60, 10)).not.toContain("NaN"));
});
