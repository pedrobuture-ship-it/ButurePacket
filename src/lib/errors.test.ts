import { describe, expect, it } from "vitest";
import { describeError } from "./errors";
import { FilterError } from "@/lib/filter";

describe("describeError", () => {
  it("maps backend errors to categories and keeps their hint", () => {
    const e = describeError({ kind: "permissionDenied", message: "Unable to start capture on eth0. Packet capture permission is not available for this interface.", hint: "Open the Capture screen." });
    expect(e).toMatchObject({ category: "permission", title: "Permission error", hint: "Open the Capture screen." });
    expect(e.message).toContain("eth0");
  });

  it.each([
    ["invalidCaptureFile", "corrupt-capture"],
    ["io", "file"],
    ["storage", "disk"],
    ["interfaceNotFound", "capture"],
    ["busy", "capture"],
    ["packetNotFound", "memory"],
    ["unavailable", "unavailable"],
    ["somethingNew", "internal"],
  ])("categorises %s as %s", (kind, category) => {
    expect(describeError({ kind, message: "x" }).category).toBe(category);
  });

  it("describes filter errors with advice", () => {
    const e = describeError(new FilterError('Unexpected token ">>" at position 13.', 13));
    expect(e.category).toBe("filter");
    expect(e.message).toBe('Unexpected token ">>" at position 13.');
    expect(e.hint).toMatch(/Tab/);
  });

  it("sanitises untrusted text inside messages", () => {
    expect(describeError({ kind: "io", message: "Cannot read \u001b[31mevil.pcap" }).message).toBe("Cannot read ·[31mevil.pcap");
  });

  it("copes with anything", () => {
    for (const odd of [undefined, null, 42, "", {}, [], new Error(""), "plain text"]) {
      const e = describeError(odd);
      expect(e.message.length).toBeGreaterThan(0);
      expect(e.category).toBe("internal");
    }
    expect(describeError("plain text").message).toBe("plain text");
  });
});
