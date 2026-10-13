import { describe, expect, it } from "vitest";
import { formatBytes, formatCount, formatDuration, formatPercent, formatRate } from "./format";

describe("format", () => {
  it("formats counts with separators", () => expect(formatCount(1423887)).toBe("1,423,887"));
  it("formats rates", () => {
    expect(formatRate(12400)).toBe("12.4 K");
    expect(formatRate(950)).toBe("950");
    expect(formatRate(2_500_000)).toBe("2.5 M");
  });
  it("formats bytes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(18.4 * 1024 * 1024)).toBe("18.4 MB");
  });
  it("formats durations", () => {
    expect(formatDuration(872_000)).toBe("00:14:32");
    expect(formatDuration(-5)).toBe("00:00:00");
  });
  it("formats percent", () => expect(formatPercent(0.24)).toBe("24%"));
});
