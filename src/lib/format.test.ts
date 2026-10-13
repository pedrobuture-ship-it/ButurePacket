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

import { formatTimestamp } from "./format";

describe("formatTimestamp", () => {
  it("renders local time with milliseconds", () => {
    const d = new Date(2024, 11, 14, 14, 22, 1, 210);
    expect(formatTimestamp(d.getTime() * 1000)).toBe("14:22:01.210");
  });
});

import { formatLatency, formatSpan } from "./format";

describe("formatSpan / formatLatency", () => {
  it("formats flow durations", () => {
    expect(formatSpan(8_400_000)).toBe("8.4s");
    expect(formatSpan(125_000_000)).toBe("2m 05s");
    expect(formatSpan(3_720_000_000)).toBe("1h 02m");
    expect(formatSpan(-1)).toBe("0.0s");
  });
  it("formats latency", () => {
    expect(formatLatency(null)).toBe("—");
    expect(formatLatency(340)).toBe("340 µs");
    expect(formatLatency(21_000)).toBe("21 ms");
    expect(formatLatency(21_400)).toBe("21.4 ms");
    expect(formatLatency(250_000)).toBe("250 ms");
  });
});

import { formatAgo } from "./format";

describe("formatAgo", () => {
  const now = 1_700_000_000_000;
  it("uses coarse relative units", () => {
    expect(formatAgo(now - 10_000, now)).toBe("just now");
    expect(formatAgo(now - 5 * 60_000, now)).toBe("5 min ago");
    expect(formatAgo(now - 3 * 3_600_000, now)).toBe("3 h ago");
    expect(formatAgo(now - 2 * 86_400_000, now)).toBe("2 d ago");
    expect(formatAgo(now + 5_000, now)).toBe("just now"); // clock skew never goes negative
  });
});
