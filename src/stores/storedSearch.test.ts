import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PAGE_SIZE, useStoredSearch } from "./storedSearch";
import type { PacketSummary } from "@/types/ipc";

const row = (id: number) => ({ id }) as PacketSummary;
const s = () => useStoredSearch.getState();

function backend(handler: (query: Record<string, unknown>) => unknown) {
  vi.stubGlobal("window", { __TAURI_INTERNALS__: { invoke: async (_cmd: string, args: { query: Record<string, unknown> }) => handler(args.query) } });
}

describe("stored search store", () => {
  beforeEach(() => s().reset());
  afterEach(() => vi.unstubAllGlobals());

  it("loads a page and remembers the overall total", async () => {
    backend((q) => ({ packets: [row(1), row(2)], total: 12345, echo: q }));
    s().setEnabled(true);
    await s().load({ ip: "10.0.0.1" });
    expect(s().rows.map((r) => r.id)).toEqual([1, 2]);
    expect(s().total).toBe(12345);
    expect(s().loading).toBe(false);
  });

  it("requests a bounded page and pages by keyset", async () => {
    const seen: Record<string, unknown>[] = [];
    backend((q) => {
      seen.push(q);
      return seen.length === 1 ? { packets: [row(1), row(2)], total: 3 } : { packets: [row(3)], total: 3 };
    });
    await s().load({ domain: "x.com" });
    await s().loadMore({ domain: "x.com" });
    expect(seen[0]).toEqual({ domain: "x.com", limit: PAGE_SIZE });
    expect(seen[1]).toEqual({ domain: "x.com", afterId: 2, limit: PAGE_SIZE });
    expect(s().rows.map((r) => r.id)).toEqual([1, 2, 3]);
  });

  it("ignores a response that was superseded by a newer search", async () => {
    let release!: (v: unknown) => void;
    let calls = 0;
    vi.stubGlobal("window", {
      __TAURI_INTERNALS__: {
        invoke: () => (++calls === 1 ? new Promise((r) => (release = r)) : Promise.resolve({ packets: [row(9)], total: 1 })),
      },
    });
    const slow = s().load({ ip: "1.1.1.1" });
    await s().load({ ip: "2.2.2.2" });
    release({ packets: [row(1)], total: 1 });
    await slow;
    expect(s().rows.map((r) => r.id)).toEqual([9]);
  });

  it("reports failures in plain language and keeps the app usable", async () => {
    backend(() => {
      throw { kind: "storage", message: "There is no stored capture to search yet.", hint: "Start a capture first." };
    });
    await s().load({});
    expect(s().error).toMatchObject({ category: "disk", hint: "Start a capture first." });
    expect(s().rows).toEqual([]);
    expect(s().loading).toBe(false);
  });

  it("clears results when disabled or when the filter is unsupported", async () => {
    backend(() => ({ packets: [row(1)], total: 1 }));
    s().setEnabled(true);
    await s().load({});
    s().setUnsupported("'||' cannot be searched in the stored capture");
    expect(s().rows).toEqual([]);
    expect(s().unsupported).toContain("'||'");
    await s().load({});
    expect(s().unsupported).toBeNull();
    s().setEnabled(false);
    expect(s().rows).toEqual([]);
  });
});
