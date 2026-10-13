import { describe, expect, it } from "vitest";
import { applySuggestion, suggest } from "./suggest";

const recents = { ips: ["192.168.1.20", "8.8.8.8"], domains: ["api.github.com", "cdn.example.org"] };
const labels = (text: string, cursor = text.length) => suggest(text, cursor, recents).items.map((i) => i.label);

describe("autocomplete", () => {
  it("offers fields and protocols at the start", () => {
    const l = labels("");
    expect(l).toContain("ip");
    expect(labels("d")).toEqual(expect.arrayContaining(["dst.ip", "dst.port", "domain", "dns"]));
    expect(labels("d").every((x) => x.includes("d"))).toBe(true);
  });
  it("ranks prefix matches before substring matches", () => {
    const l = labels("po");
    expect(l[0]).toBe("port");
    expect(l).toEqual(expect.arrayContaining(["src.port", "dst.port"]));
    expect(l.indexOf("port")).toBeLessThan(l.indexOf("dst.port")); // prefix match first, substring after
  });
  it("offers operators for a field, limited to valid ones", () => {
    expect(labels("dst.port ")).toEqual(["=", "!=", ">", ">=", "<", "<="]);
    expect(labels("ip ")).toEqual(["=", "!="]);
    expect(labels("domain ")).toContain("contains");
    expect(labels("domain co")).toEqual(["contains"]);
  });
  it("offers values: protocols, recent IPs and recent domains", () => {
    expect(labels("protocol = t")).toEqual(expect.arrayContaining(["tcp", "tls"]));
    expect(labels("ip = ")).toEqual(["192.168.1.20", "8.8.8.8"]);
    expect(labels("src.ip = 19")).toEqual(["192.168.1.20"]);
    expect(labels("domain contains ")).toEqual(["api.github.com", "cdn.example.org"]);
    expect(labels("domain = git")).toEqual(["api.github.com"]);
    expect(labels("flags contains ")).toContain("syn");
    expect(labels("latency > ")).toContain("100ms");
    expect(labels("bytes > ")).toContain("1MB");
  });
  it("offers logical operators after a complete condition or protocol", () => {
    expect(labels("tcp ")).toEqual(["&&", "||"]);
    expect(labels("dst.port = 443 ")).toEqual(["&&", "||"]);
    expect(labels("(tcp) ")).toEqual(["&&", "||"]);
  });
  it("starts a new condition after && / || / ! / (", () => {
    expect(labels("tcp && ")).toContain("dst.port");
    expect(labels("tcp || d")).toContain("domain");
    expect(labels("!")).toContain("tcp");
    expect(labels("(")).toContain("ip");
  });
  it("works mid-string using the cursor position", () => {
    const text = "tcp && dst.p || udp";
    const cursor = "tcp && dst.p".length;
    expect(labels(text, cursor)).toEqual(expect.arrayContaining(["dst.port"]));
  });
  it("is silent for values it can't guess and never throws on broken input", () => {
    expect(labels("dst.port = ")).toEqual([]);
    expect(labels("ip >> ")).toBeTruthy();
    expect(() => suggest('domain = "abc', 13, recents)).not.toThrow();
    expect(() => suggest("((((", 4, recents)).not.toThrow();
  });
  it("applies a suggestion in place and moves the cursor", () => {
    const text = "tcp && dst.p";
    const s = suggest(text, text.length, recents);
    const item = s.items.find((i) => i.label === "dst.port")!;
    expect(applySuggestion(text, s, item)).toEqual({ text: "tcp && dst.port", cursor: "tcp && dst.port".length });
    const t2 = "ip = ";
    const s2 = suggest(t2, t2.length, recents);
    expect(applySuggestion(t2, s2, s2.items[0]).text).toBe("ip = 192.168.1.20");
  });
  it("quotes recent domains that contain spaces", () => {
    const s = suggest("domain = ", 9, { ips: [], domains: ["has space.example"] });
    expect(s.items[0].insert).toBe('"has space.example"');
  });
});
