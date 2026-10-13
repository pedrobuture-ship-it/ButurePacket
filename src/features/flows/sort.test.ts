import { describe, expect, it } from "vitest";
import { sortFlows } from "./sort";
import { makeFlow } from "./testFlow";

const flows = [
  makeFlow({ id: 1, totalBytes: 100, duration: 5, latency: null, totalPackets: 9, startedAt: 30 }),
  makeFlow({ id: 2, totalBytes: 900, duration: 1, latency: 20_000, totalPackets: 3, startedAt: 10 }),
  makeFlow({ id: 3, totalBytes: 500, duration: 9, latency: 5_000, totalPackets: 5, startedAt: 20 }),
];
const ids = (s: Parameters<typeof sortFlows>[1]) => sortFlows(flows, s).map((f) => f.id);

describe("sortFlows", () => {
  it("sorts by traffic, duration, packets", () => {
    expect(ids("traffic")).toEqual([2, 3, 1]);
    expect(ids("duration")).toEqual([3, 1, 2]);
    expect(ids("packets")).toEqual([1, 3, 2]);
  });
  it("puts flows without latency last", () => expect(ids("latency")).toEqual([2, 3, 1]));
  it("sorts by age", () => {
    expect(ids("newest")).toEqual([1, 3, 2]);
    expect(ids("oldest")).toEqual([2, 3, 1]);
  });
  it("does not mutate its input and is stable on ties", () => {
    const tie = [makeFlow({ id: 5, totalBytes: 1 }), makeFlow({ id: 4, totalBytes: 1 })];
    expect(sortFlows(tie, "traffic").map((f) => f.id)).toEqual([4, 5]);
    expect(tie.map((f) => f.id)).toEqual([5, 4]);
  });
});
