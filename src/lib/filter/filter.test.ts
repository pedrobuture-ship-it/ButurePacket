import { describe, expect, it } from "vitest";
import { evaluate, parseFilter, type FieldValue, type Subject } from "./index";
import { lex } from "./lexer";
import { cidrContains, parseAddress, parseCidr, parseIPv6 } from "./values";

/** A tiny packet-like subject for tests. */
function subject(fields: Record<string, FieldValue>, protocols: string[] = []): Subject {
  return { get: (f) => fields[f], protocols: () => protocols };
}

const pkt = subject(
  {
    ip: ["192.168.1.20", "140.82.121.4"],
    "src.ip": "192.168.1.20",
    "dst.ip": "140.82.121.4",
    port: [53214, 443],
    "src.port": 53214,
    "dst.port": 443,
    length: 1460,
    bytes: 1460,
    ttl: 64,
    flags: ["syn", "ack"],
    domain: ["api.github.com"],
    info: "53214 → 443 [SYN, ACK]",
    latency: 21_000,
    mac: ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
    "src.mac": "aa:bb:cc:dd:ee:ff",
  },
  ["ipv4", "tcp", "tls"],
);

const ok = (text: string, s: Subject = pkt) => {
  const r = parseFilter(text);
  if (!r.ok) throw new Error(`parse failed for "${text}": ${r.error.message}`);
  return evaluate(r.ast, s);
};
const err = (text: string) => {
  const r = parseFilter(text);
  if (r.ok) throw new Error(`expected "${text}" to fail`);
  return r.error;
};

describe("lexer", () => {
  it("tokenises operators, words, strings and parentheses", () => {
    const { tokens, error } = lex('tcp && (dst.port = 443 || domain contains "git hub")');
    expect(error).toBeUndefined();
    expect(tokens.map((t) => t.type)).toEqual(["word", "and", "lparen", "word", "op", "word", "or", "word", "op", "string", "rparen"]);
    expect(tokens[9].text).toBe("git hub");
    expect(tokens[1].pos).toBe(4);
  });
  it("normalises == and keyword operators/logic", () => {
    const t = lex("a == b AND NOT c Contains d OR e").tokens;
    expect(t.map((x) => `${x.type}:${x.text}`)).toEqual(["word:a", "op:=", "word:b", "and:and", "not:not", "word:c", "op:contains", "word:d", "or:or", "word:e"]);
  });
  it("supports escapes and both quote styles", () => {
    expect(lex(String.raw`info = "say \"hi\""`).tokens[2].text).toBe('say "hi"');
    expect(lex("info = 'it''s'").tokens.length).toBe(4);
  });
  it("keeps IPv6, CIDR, MAC and unit tokens in one word", () => {
    const words = lex("a = fe80::1 b = 10.0.0.0/8 c = aa:bb:cc d = 100ms").tokens.filter((t) => t.type === "word" && /[:/.0-9]/.test(t.text));
    expect(words.map((w) => w.text)).toEqual(["fe80::1", "10.0.0.0/8", "aa:bb:cc", "100ms"]);
  });
  it("reports bad operators with their position", () => {
    expect(lex("latency >> 50ms").error?.message).toBe('Unexpected token ">>" at position 8.');
    expect(lex("ip === 1.1.1.1").error?.message).toBe('Unexpected token "===" at position 3.');
    expect(lex("a & b").error?.message).toBe('Unexpected token "&" at position 2.');
  });
  it("reports unterminated strings", () => {
    expect(lex('domain = "abc').error?.message).toBe("Unterminated string starting at position 9.");
  });
});

describe("parser: valid filters", () => {
  it("treats an empty filter as match-all", () => {
    expect(parseFilter("")).toEqual({ ok: true, ast: null });
    expect(parseFilter("   \t ")).toEqual({ ok: true, ast: null });
    expect(ok("")).toBe(true);
  });
  it("accepts every example from the spec", () => {
    for (const f of ["tcp", "udp", "dns", "ip = 192.168.1.20", "src.ip = 192.168.1.20", "dst.port = 443", 'domain contains "github"', "latency > 100ms", "bytes > 1MB", "tcp && dst.port = 443", "dns && latency > 50ms"]) {
      expect(parseFilter(f).ok, f).toBe(true);
    }
  });
  it("applies precedence: not > and > or", () => {
    const only = (names: string[]) => subject({}, names);
    expect(ok("tcp || udp && dns", only(["tcp"]))).toBe(true); // tcp || (udp && dns)
    expect(ok("(tcp || udp) && dns", only(["tcp"]))).toBe(false);
    expect(ok("!tcp", only(["udp"]))).toBe(true);
    expect(ok("not tcp and udp", only(["udp"]))).toBe(true);
    expect(ok("!(tcp or udp)", only(["tcp"]))).toBe(false);
    expect(ok("!!tcp", only(["tcp"]))).toBe(true);
  });
  it("is case-insensitive for fields, keywords and protocols", () => {
    expect(ok("TCP AND DST.PORT = 443")).toBe(true);
    expect(ok("Domain CONTAINS GitHub")).toBe(true);
  });
  it("accepts aliases", () => {
    expect(ok("proto = tcp")).toBe(true);
    expect(ok("len > 1000")).toBe(true);
    expect(ok("https")).toBe(true); // alias of tls
  });
});

describe("evaluation semantics", () => {
  it("matches protocols by bare word and by field", () => {
    expect(ok("tcp")).toBe(true);
    expect(ok("udp")).toBe(false);
    expect(ok("protocol = tls")).toBe(true);
    expect(ok("protocol != tcp")).toBe(false);
    expect(ok("ip")).toBe(false); // bare "ip" means the protocol name; subject only lists ipv4
  });
  it("matches either side for symmetric fields", () => {
    expect(ok("ip = 140.82.121.4")).toBe(true);
    expect(ok("ip = 192.168.1.20")).toBe(true);
    expect(ok("ip = 8.8.8.8")).toBe(false);
    expect(ok("src.ip = 140.82.121.4")).toBe(false);
    expect(ok("dst.ip = 140.82.121.4")).toBe(true);
    expect(ok("port = 53214")).toBe(true);
    expect(ok("port = 443")).toBe(true);
    expect(ok("port = 80")).toBe(false);
  });
  it("`!=` excludes everything involving the value", () => {
    expect(ok("ip != 8.8.8.8")).toBe(true);
    expect(ok("ip != 140.82.121.4")).toBe(false);
    expect(ok("port != 443")).toBe(false);
  });
  it("supports CIDR ranges for IPv4 and IPv6", () => {
    expect(ok("ip = 192.168.0.0/16")).toBe(true);
    expect(ok("ip = 10.0.0.0/8")).toBe(false);
    expect(ok("src.ip = 192.168.1.20/32")).toBe(true);
    expect(ok("ip = fe80::/10", subject({ ip: ["fe80::1ff:fe23:4567:890a"] }))).toBe(true);
    expect(ok("ip = 2001:db8::/32", subject({ ip: ["2001:db9::1"] }))).toBe(false);
    expect(ok("ip = ::1", subject({ ip: ["::1"] }))).toBe(true);
    expect(ok("ip = 0.0.0.0/0")).toBe(true);
    expect(ok("ip = 0.0.0.0/0", subject({ ip: ["::1"] }))).toBe(false); // families never mix
  });
  it("compares numbers with units", () => {
    expect(ok("bytes > 1KB")).toBe(true);
    expect(ok("bytes > 1MB")).toBe(false);
    expect(ok("bytes >= 1460")).toBe(true);
    expect(ok("bytes < 1.5kb")).toBe(true);
    expect(ok("latency > 20ms")).toBe(true);
    expect(ok("latency > 21ms")).toBe(false);
    expect(ok("latency <= 21000us")).toBe(true);
    expect(ok("latency < 1s")).toBe(true);
    expect(ok("latency > 20")).toBe(true); // bare numbers are milliseconds
    expect(ok("ttl = 64")).toBe(true);
    expect(ok("ttl < 64")).toBe(false);
  });
  it("matches text case-insensitively", () => {
    expect(ok('domain contains "GITHUB"')).toBe(true);
    expect(ok("domain startswith api.")).toBe(true);
    expect(ok("domain endswith .com")).toBe(true);
    expect(ok("domain = api.github.com")).toBe(true);
    expect(ok("domain != api.github.com")).toBe(false);
    expect(ok('info contains "[SYN"')).toBe(true);
  });
  it("matches TCP flags and MACs", () => {
    expect(ok("flags contains syn")).toBe(true);
    expect(ok("flags = ack")).toBe(true);
    expect(ok("flags contains rst")).toBe(false);
    expect(ok("mac = AA:BB:CC:DD:EE:FF")).toBe(true);
    expect(ok("src.mac contains aa:bb")).toBe(true);
    expect(ok("mac = aa-bb-cc-dd-ee-ff")).toBe(true);
  });
  it("missing fields never match except through !=", () => {
    const flowLike = subject({ bytes: 10 }, ["tcp"]);
    expect(ok("ttl = 64", flowLike)).toBe(false);
    expect(ok("ttl > 0", flowLike)).toBe(false);
    expect(ok("ttl != 64", flowLike)).toBe(true);
    expect(ok("domain contains x", flowLike)).toBe(false);
  });
  it("combines the spec examples", () => {
    expect(ok("tcp && dst.port = 443")).toBe(true);
    expect(ok("dns && latency > 50ms", subject({ latency: 80_000 }, ["dns"]))).toBe(true);
    expect(ok("dns && latency > 50ms", subject({ latency: 20_000 }, ["dns"]))).toBe(false);
    expect(ok("dns && latency > 50ms")).toBe(false); // not DNS
  });
});

describe("parser: errors", () => {
  it("rejects unknown fields with a suggestion", () => {
    expect(err("dst.prot = 443").message).toBe('Unknown field or protocol "dst.prot" at position 0. Did you mean "dst.port"?');
    expect(err("tcp && domian contains x").message).toContain('Did you mean "domain"?');
    expect(err("zzzz").message).toBe('Unknown field or protocol "zzzz" at position 0.');
  });
  it("reports unexpected operators like the spec example", () => {
    expect(err("latency >> 50ms").message).toBe('Unexpected token ">>" at position 8.');
    expect(err("dst.port > > 443").message).toBe('Unexpected token ">" at position 11.');
  });
  it("rejects operators that don't suit the field", () => {
    expect(err("ip > 1.1.1.1").message).toContain('Operator ">" cannot be used with "ip"');
    expect(err("domain > 5").message).toContain("Allowed: =, !=, contains, startswith, endswith");
    expect(err("flags > syn").message).toContain('cannot be used with "flags"');
  });
  it("rejects malformed values", () => {
    expect(err("ip = 300.1.1.1").message).toContain("not a valid IP address");
    expect(err("ip = 1.2.3.4/40").message).toContain("not a valid IP address");
    expect(err("dst.port = 70000").message).toContain("between 0 and 65535");
    expect(err("dst.port = 8o").message).toContain("unexpected unit");
    expect(err("bytes > 1XB").message).toContain('Unknown size unit "XB"');
    expect(err("latency > 5parsecs").message).toContain('Unknown time unit "parsecs"');
    expect(err("bytes > abc").message).toContain("Expected a number");
    expect(err('dst.port = "443"').message).toContain("Expected a number");
    expect(err("flags contains zap").message).toContain('Unknown TCP flag "zap"');
    expect(err("mac = zz:zz").message).toContain("not a valid MAC");
  });
  it("rejects structural mistakes", () => {
    expect(err("tcp &&").message).toBe("Unexpected end of filter.");
    expect(err("&& tcp").message).toBe('Unexpected token "&&" at position 0.');
    expect(err("(tcp").message).toBe('Missing closing parenthesis for "(" at position 0.');
    expect(err("tcp)").message).toBe('Unexpected token ")" at position 3.');
    expect(err("dst.port =").message).toBe('Missing value after "dst.port =" at position 10.');
    expect(err("dst.port").message).toBe('Field "dst.port" needs an operator and a value (position 0).');
    expect(err("tcp udp").message).toBe('Unexpected token "udp" at position 4.');
    expect(err("dst.port = (443)").message).toBe('Unexpected token "(" at position 11.');
    expect(err("= 5").message).toBe('Unexpected token "=" at position 0.');
  });
  it("carries a numeric position on every error", () => {
    for (const bad of ["tcp &&", "((", "ip = x", "latency >> 1"]) expect(Number.isInteger(err(bad).position)).toBe(true);
  });
  it("bounds nesting depth instead of overflowing the stack", () => {
    expect(err("(".repeat(500) + "tcp" + ")".repeat(500)).message).toBe("Filter is nested too deeply.");
    expect(err("!".repeat(500) + "tcp").message).toBe("Filter is nested too deeply.");
    expect(parseFilter("(".repeat(20) + "tcp" + ")".repeat(20)).ok).toBe(true);
  });
});

describe("hostile input", () => {
  it("never executes anything and never throws non-FilterErrors", () => {
    const nasty = ["__proto__ = 1", "constructor", "ip = ${process.exit()}", "domain = `rm -rf /`", "(() => 1)()", "tcp; drop table", "\u0000\u001b[31m", "a".repeat(10_000), '"'.repeat(5), "ip = " + "9".repeat(5000), "toString", "info contains " + "x".repeat(100_000)];
    for (const n of nasty) {
      const r = parseFilter(n);
      if (!r.ok) expect(r.error.name).toBe("FilterError");
    }
  });
  it("handles long chains iteratively enough", () => {
    const f = Array.from({ length: 3000 }, () => "tcp").join(" || ");
    const r = parseFilter(f);
    expect(r.ok).toBe(true);
  });
});

describe("address helpers", () => {
  it("parses IPv6 shorthand", () => {
    expect(parseIPv6("::")).toBe(0n);
    expect(parseIPv6("::1")).toBe(1n);
    expect(parseIPv6("1::")).toBe(1n << 112n);
    expect(parseIPv6("::ffff:1.2.3.4")).toBe(0xffff01020304n);
    expect(parseIPv6("1:2:3:4:5:6:7:8")).toBe(0x00010002000300040005000600070008n);
    for (const bad of [":::", "1::2::3", "12345::", "g::1", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7"]) expect(parseIPv6(bad), bad).toBeNull();
  });
  it("parses and matches CIDRs", () => {
    expect(parseCidr("10.0.0.0/8")).toMatchObject({ family: 4, bits: 8 });
    expect(parseCidr("10.1.2.3/8")?.base).toBe(parseCidr("10.0.0.0/8")?.base); // host bits dropped
    expect(parseCidr("10.0.0.0/33")).toBeNull();
    expect(parseCidr("10.0.0.0/8/8")).toBeNull();
    expect(cidrContains(parseCidr("192.168.0.0/16")!, "192.168.200.1")).toBe(true);
    expect(cidrContains(parseCidr("192.168.0.0/16")!, "192.169.0.1")).toBe(false);
    expect(parseAddress("not an ip")).toBeNull();
  });
});
