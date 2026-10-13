import { beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_FLOWS, flowBuffer, useFlowsStore } from "./flows";
import { makeFlow } from "@/features/flows/testFlow";

describe("flows store", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    useFlowsStore.getState().clear();
  });

  it("upserts by id and coalesces version bumps", () => {
    const v0 = useFlowsStore.getState().version;
    useFlowsStore.getState().upsert([makeFlow({ id: 1, totalBytes: 10 })]);
    useFlowsStore.getState().upsert([makeFlow({ id: 1, totalBytes: 20 }), makeFlow({ id: 2 })]);
    expect(useFlowsStore.getState().version).toBe(v0);
    vi.advanceTimersByTime(300);
    expect(useFlowsStore.getState().version).toBe(v0 + 1);
    expect(flowBuffer.byId.size).toBe(2);
    expect(flowBuffer.byId.get(1)?.totalBytes).toBe(20);
  });

  it("clear removes flows and selection", () => {
    useFlowsStore.getState().upsert([makeFlow({ id: 1 })]);
    useFlowsStore.getState().select(1);
    useFlowsStore.getState().clear();
    expect(flowBuffer.byId.size).toBe(0);
    expect(useFlowsStore.getState().selectedId).toBeNull();
  });

  it("evicts the least recently seen flows once well past the cap", () => {
    const many = Array.from({ length: Math.ceil(MAX_FLOWS * 1.1) + 5 }, (_, i) => makeFlow({ id: i + 1, lastSeenAt: i }));
    useFlowsStore.getState().upsert(many);
    expect(flowBuffer.byId.size).toBe(MAX_FLOWS);
    expect(flowBuffer.byId.has(1)).toBe(false);
    expect(flowBuffer.byId.has(many.length)).toBe(true);
  });
});
