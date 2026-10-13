import { describe, expect, it } from "vitest";
import { parseFilter } from "./index";
import { toStoredQuery } from "./stored";

const q = (text: string) => {
  const r = parseFilter(text);
  if (!r.ok) throw r.error;
  return toStoredQuery(r.ast);
};

describe("toStoredQuery", () => {
  it("accepts no filter as 'everything'", () => expect(toStoredQuery(null)).toEqual({ ok: true, query: {} }));

  it("maps indexed conditions joined with &&", () => {
    expect(q("ip = 192.168.1.20")).toEqual({ ok: true, query: { ip: "192.168.1.20" } });
    expect(q("src.ip = 10.0.0.1 && dst.ip = 8.8.8.8 && dns")).toEqual({ ok: true, query: { srcIp: "10.0.0.1", dstIp: "8.8.8.8", protocol: "dns" } });
    expect(q("flow = 7 && domain = Api.GitHub.com")).toEqual({ ok: true, query: { flowId: 7, domain: "api.github.com" } });
    expect(q("protocol = tls")).toEqual({ ok: true, query: { protocol: "tls" } });
    expect(q("ip = ::1")).toEqual({ ok: true, query: { ip: "::1" } });
    expect(q("https")).toEqual({ ok: true, query: { protocol: "tls" } });
  });

  it.each([
    ["tcp || udp", "'||'"],
    ["!dns", "'!'"],
    ["dst.port = 443", "not indexed"],
    ["bytes > 1MB", "'>'"],
    ["ip = 10.0.0.0/8", "CIDR"],
    ["domain contains git", "'contains'"],
    ["tcp && udp", "more than once"],
    ["ip != 1.2.3.4", "'!='"],
  ])("explains why %s cannot be searched", (text, fragment) => {
    const r = q(text);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain(fragment);
  });

  it("treats a /32 host route as a single address", () => {
    expect(q("ip = 1.2.3.4/32")).toEqual({ ok: true, query: { ip: "1.2.3.4" } });
  });
});
