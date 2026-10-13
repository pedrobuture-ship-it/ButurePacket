import { describe, expect, it } from "vitest";
import { useAppStore } from "./app";

describe("app store", () => {
  it("stores backend info", () => {
    useAppStore.getState().setInfo({ name: "ButurePacket", version: "0.1.0", platform: "linux" });
    expect(useAppStore.getState().info?.name).toBe("ButurePacket");
  });
});
