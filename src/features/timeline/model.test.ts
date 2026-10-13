import { describe, expect, it } from "vitest";
import { clampRange, formatClock, groupOf, lowerBound, matchesFilter, niceTicks, panRange, timeToX, xToTime, zoomRange, type EventFilter } from "./model";
import type { TimelineEvent } from "@/types/ipc";

const ev = (over: Partial<TimelineEvent> = {}): TimelineEvent => ({ id: 1, ts: 0, kind: "dnsQuery", flowId: null, host: "8.8.8.8", domain: "api.github.com", title: "DNS api.github.com", detail: "A via 8.8.8.8", ...over });
const all: EventFilter = { groups: new Set(["dns", "tcp", "tls", "problems", "traffic"]), text: "", flowId: null };

describe("event filtering", () => {
  it("groups kinds into lanes", () => {
    expect(groupOf("dnsFailure")).toBe("dns");
    expect(groupOf("retransmission")).toBe("problems");
    expect(groupOf("trafficBurst")).toBe("traffic");
    expect(groupOf("tcpConnect")).toBe("tcp");
  });
  it("filters by group, flow and text across host/domain/title", () => {
    expect(matchesFilter(ev(), all)).toBe(true);
    expect(matchesFilter(ev(), { ...all, groups: new Set(["tcp"]) })).toBe(false);
    expect(matchesFilter(ev({ flowId: 3 }), { ...all, flowId: 3 })).toBe(true);
    expect(matchesFilter(ev({ flowId: 4 }), { ...all, flowId: 3 })).toBe(false);
    expect(matchesFilter(ev(), { ...all, text: "GITHUB" })).toBe(true);
    expect(matchesFilter(ev(), { ...all, text: "8.8.8" })).toBe(true);
    expect(matchesFilter(ev(), { ...all, text: "gitlab" })).toBe(false);
    expect(matchesFilter(ev({ host: null, domain: null, detail: null }), { ...all, text: "x" })).toBe(false);
  });
});

describe("time axis maths", () => {
  const view = { start: 1000, end: 2000 };
  it("maps time to x and back", () => {
    expect(timeToX(1500, view, 500)).toBe(250);
    expect(xToTime(250, view, 500)).toBe(1500);
    expect(timeToX(5, { start: 5, end: 5 }, 100)).toBe(0);
  });
  it("zooms around the anchor and keeps its screen position", () => {
    const bounds = { start: 0, end: 10_000_000 };
    const v = { start: 4_000_000, end: 6_000_000 };
    const z = zoomRange(v, 5_000_000, 0.5, bounds);
    expect(z.end - z.start).toBe(1_000_000);
    expect((5_000_000 - z.start) / (z.end - z.start)).toBeCloseTo(0.5);
  });
  it("never zooms out past the data or in past 1ms", () => {
    const bounds = { start: 0, end: 1_000_000 };
    expect(zoomRange({ start: 0, end: 1_000_000 }, 5, 10, bounds)).toEqual(bounds);
    const tiny = zoomRange({ start: 0, end: 2_000 }, 1_000, 0.0001, bounds);
    expect(tiny.end - tiny.start).toBe(1_000);
  });
  it("pans within bounds", () => {
    const bounds = { start: 0, end: 100 };
    expect(panRange({ start: 10, end: 30 }, 1000, bounds)).toEqual({ start: 80, end: 100 });
    expect(panRange({ start: 10, end: 30 }, -1000, bounds)).toEqual({ start: 0, end: 20 });
    expect(clampRange({ start: -5, end: 500 }, bounds)).toEqual(bounds);
  });
  it("produces round ticks inside the view", () => {
    const ticks = niceTicks({ start: 0, end: 10_000_000 }, 10);
    expect(ticks[0]).toBe(0);
    expect(ticks[1] - ticks[0]).toBe(1_000_000);
    expect(ticks.every((t) => t >= 0 && t <= 10_000_000)).toBe(true);
    expect(niceTicks({ start: 5, end: 5 })).toEqual([]);
  });
  it("formats clock times", () => {
    const t = new Date(2024, 11, 14, 14, 22, 1, 210).getTime() * 1000;
    expect(formatClock(t, true)).toBe("14:22:01.210");
    expect(formatClock(t, false)).toBe("14:22:01");
  });
  it("binary-searches events by time", () => {
    const evs = [0, 10, 10, 20].map((ts, i) => ev({ id: i, ts }));
    expect(lowerBound(evs, 10)).toBe(1);
    expect(lowerBound(evs, 11)).toBe(3);
    expect(lowerBound(evs, 99)).toBe(4);
    expect(lowerBound([], 1)).toBe(0);
  });
});
