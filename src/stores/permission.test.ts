import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { usePermissionStore } from "./permission";

describe("permission store", () => {
  beforeEach(() => usePermissionStore.setState({ report: null, checking: false, error: null }));
  afterEach(() => vi.unstubAllGlobals());

  it("reports a friendly error when the backend is unreachable (plain browser)", async () => {
    const r = await usePermissionStore.getState().check();
    expect(r).toBeNull();
    expect(usePermissionStore.getState()).toMatchObject({ checking: false, error: "B&M Packet must run inside the desktop app." });
  });

  it("stores the report from the backend", async () => {
    vi.stubGlobal("window", { __TAURI_INTERNALS__: { invoke: async () => ({ state: "available", summary: "ok", interfaces: [], guidance: [], commands: [] }) } });
    const r = await usePermissionStore.getState().check();
    expect(r?.state).toBe("available");
    expect(usePermissionStore.getState().report?.summary).toBe("ok");
    expect(usePermissionStore.getState().error).toBeNull();
  });
});
