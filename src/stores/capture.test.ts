import { beforeEach, describe, expect, it } from "vitest";
import { useCaptureStore } from "./capture";

const s = () => useCaptureStore.getState();

describe("capture store: live vs offline", () => {
  beforeEach(() => {
    s().reset();
    s().setMode("live");
  });

  it("starts in live mode with no file", () => {
    expect(s().mode).toBe("live");
    expect(s().fileName).toBeNull();
  });

  it("remembers the file name only while offline", () => {
    s().setMode("offline", "traffic.pcap");
    expect(s()).toMatchObject({ mode: "offline", fileName: "traffic.pcap" });
    s().setMode("live", "ignored.pcap");
    expect(s()).toMatchObject({ mode: "live", fileName: null });
  });

  it("reset keeps the mode but clears stats, errors and progress", () => {
    s().setMode("offline", "a.pcap");
    s().applyStats({ ...s().stats, packets: 5 });
    s().setOpenProgress({ fileName: "a.pcap", done: false, cancelled: false, error: null, rowsTruncated: false, truncatedTail: false, skipped: 0 });
    s().fail("boom");
    s().reset();
    expect(s().stats.packets).toBe(0);
    expect(s().openProgress).toBeNull();
    expect(s().error).toBeNull();
    expect(s().state).toBe("idle");
    expect(s().mode).toBe("offline");
  });

  it("keeps the failure message when moving to the error state", () => {
    s().fail("Permission denied");
    expect(s()).toMatchObject({ state: "error", error: "Permission denied" });
    s().setState("idle");
    expect(s().error).toBeNull();
  });

  it("picks a default interface: first up, non-loopback", () => {
    s().setInterfaces([
      { name: "lo", description: null, addresses: [], loopback: true, up: true },
      { name: "wlan0", description: null, addresses: [], loopback: false, up: false },
      { name: "eth0", description: null, addresses: [], loopback: false, up: true },
    ]);
    expect(s().selectedInterface).toBe("eth0");
    s().selectInterface("lo");
    s().setInterfaces([{ name: "eth0", description: null, addresses: [], loopback: false, up: true }]);
    expect(s().selectedInterface).toBe("lo"); // an explicit choice is not overwritten
  });
});
