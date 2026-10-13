import { beforeEach, describe, expect, it, vi } from "vitest";
import { eventBuffer, useEventsStore } from "./events";
import type { TimelineEvent } from "@/types/ipc";

const ev = (id: number): TimelineEvent => ({ id, ts: id, kind: "flowStarted", flowId: null, host: null, domain: null, title: "x", detail: null });

describe("events store", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    useEventsStore.getState().clear();
  });

  it("appends in place and coalesces version bumps", () => {
    const v0 = useEventsStore.getState().version;
    useEventsStore.getState().append([ev(1), ev(2)]);
    useEventsStore.getState().append([ev(3)]);
    expect(eventBuffer.rows.map((e) => e.id)).toEqual([1, 2, 3]);
    expect(useEventsStore.getState().version).toBe(v0);
    vi.advanceTimersByTime(300);
    expect(useEventsStore.getState().version).toBe(v0 + 1);
  });

  it("keeps only the newest events past the cap", () => {
    useEventsStore.getState().append(Array.from({ length: 300_050 }, (_, i) => ev(i + 1)));
    expect(eventBuffer.rows).toHaveLength(300_000);
    expect(eventBuffer.rows[0].id).toBe(51);
  });

  it("clear empties the buffer", () => {
    useEventsStore.getState().append([ev(1)]);
    useEventsStore.getState().clear();
    expect(eventBuffer.rows).toEqual([]);
  });
});
