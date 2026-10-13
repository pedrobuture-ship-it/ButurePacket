import { describe, expect, it } from "vitest";
import { barFractions, currentRate, latest, seriesValues, summarizeSeries, tcpHealth } from "./derive";
import type { MetricBucket } from "@/types/ipc";

const b = (sec: number, packets: number, over: Partial<MetricBucket> = {}): MetricBucket => ({ sec, span: 1, packets, bytes: packets * 100, bytesUp: 0, bytesDown: 0, newFlows: 0, activeFlows: 0, retransmissions: 0, resets: 0, duplicateAcks: 0, zeroWindows: 0, ...over });

describe("analytics derivations", () => {
  it("pads short series on the left", () => {
    expect(seriesValues([b(1, 5), b(2, 7)], "packets", 4)).toEqual([0, 0, 5, 7]);
    expect(seriesValues([b(1, 5), b(2, 7), b(3, 9)], "packets", 2)).toEqual([7, 9]);
    expect(seriesValues([], "bytes", 3)).toEqual([0, 0, 0]);
  });
  it("averages completed seconds and ignores the one still filling", () => {
    const s = [b(1, 100), b(2, 200), b(3, 300), b(4, 1)];
    expect(currentRate(s, "packets")).toBe(200);
    expect(currentRate(s, "packets", 1)).toBe(300);
    expect(currentRate([b(1, 50)], "packets")).toBe(50);
    expect(currentRate([], "packets")).toBe(0);
  });
  it("reads the latest gauge value", () => {
    expect(latest([b(1, 1, { activeFlows: 4 }), b(2, 1, { activeFlows: 9 })], "activeFlows")).toBe(9);
    expect(latest([], "activeFlows")).toBe(0);
  });
  it("computes TCP rates without dividing by zero", () => {
    expect(tcpHealth({ packets: 0, retransmissions: 0, resets: 0, duplicateAcks: 0, zeroWindows: 0 })).toEqual({ retransmissionRate: 0, resetRate: 0 });
    expect(tcpHealth({ packets: 200, retransmissions: 5, resets: 2, duplicateAcks: 0, zeroWindows: 0 })).toEqual({ retransmissionRate: 0.025, resetRate: 0.01 });
  });
  it("scales bars to the largest value", () => {
    expect(barFractions([50, 100, 25])).toEqual([0.5, 1, 0.25]);
    expect(barFractions([0, 0])).toEqual([0, 0]);
    expect(barFractions([])).toEqual([]);
  });

  it("normalises downsampled buckets to per-second values", () => {
    const s = [b(0, 1000, { span: 10 }), b(10, 3000, { span: 10 })];
    expect(seriesValues(s, "packets", 2)).toEqual([100, 300]);
    expect(currentRate([...s, b(20, 1, { span: 10 })], "packets", 2)).toBe(200);
    expect(seriesValues([b(0, 1, { span: 10, activeFlows: 50 })], "activeFlows", 1)).toEqual([50]); // gauges are not divided
  });
  it("summarises a whole capture", () => {
    const s = [b(0, 1000, { span: 10 }), b(10, 3000, { span: 10 })];
    expect(summarizeSeries(s, "packets")).toEqual({ avg: 200, peak: 300 });
    expect(summarizeSeries([], "bytes")).toEqual({ avg: 0, peak: 0 });
    expect(summarizeSeries([b(0, 0, { activeFlows: 10 }), b(1, 0, { activeFlows: 30 })], "activeFlows")).toEqual({ avg: 20, peak: 30 });
  });
});
