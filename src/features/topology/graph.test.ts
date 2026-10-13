import { describe, expect, it } from "vitest";
import { DEFAULT_OPTIONS, buildGraph, isLocalAddress, type GraphOptions } from "./graph";
import { makeFlow } from "@/features/flows/testFlow";
import type { FlowView } from "@/types/ipc";

const opts = (o: Partial<GraphOptions> = {}): GraphOptions => ({ ...DEFAULT_OPTIONS, localIps: new Set(["192.168.1.20"]), ...o });
const flow = (id: number, remote: string, over: Partial<FlowView> = {}) =>
  makeFlow({ id, endpointA: { ip: "192.168.1.20", port: 50000 + id }, endpointB: { ip: remote, port: 443 }, totalBytes: 1000, totalPackets: 10, startedAt: 100, lastSeenAt: 200, ...over });

describe("isLocalAddress", () => {
  it("classifies IPv4 ranges", () => {
    for (const ip of ["10.1.2.3", "192.168.0.1", "172.16.0.1", "172.31.255.1", "127.0.0.1", "169.254.1.1", "224.0.0.251", "255.255.255.255", "100.64.0.1"]) expect(isLocalAddress(ip), ip).toBe(true);
    for (const ip of ["8.8.8.8", "172.32.0.1", "172.15.0.1", "140.82.121.4", "1.1.1.1"]) expect(isLocalAddress(ip), ip).toBe(false);
  });
  it("classifies IPv6 ranges", () => {
    for (const ip of ["::1", "fe80::1", "fd12:3456::1", "ff02::fb"]) expect(isLocalAddress(ip), ip).toBe(true);
    for (const ip of ["2606:4700::1111", "2001:4860:4860::8888"]) expect(isLocalAddress(ip), ip).toBe(false);
  });
  it("treats garbage as remote rather than throwing", () => {
    expect(isLocalAddress("not-an-ip")).toBe(false);
    expect(isLocalAddress("999.1.1.1")).toBe(false);
  });
});

describe("buildGraph", () => {
  it("builds hosts, one edge per host pair and marks this device", () => {
    const g = buildGraph([flow(1, "140.82.121.4"), flow(2, "140.82.121.4", { totalBytes: 500 }), flow(3, "8.8.8.8")], opts());
    expect(g.nodes.filter((n) => n.kind === "this").map((n) => n.ip)).toEqual(["192.168.1.20"]);
    expect(g.nodes.filter((n) => n.kind === "remote")).toHaveLength(2);
    const github = g.edges.find((e) => e.kind === "flow" && (e.source.includes("140.82") || e.target.includes("140.82")))!;
    expect(github).toMatchObject({ flows: 2, bytes: 1500, packets: 20, duration: 100 });
    expect(github.flowIds).toEqual([1, 2]);
  });

  it("falls back to the busiest private host when the interface address is unknown", () => {
    const g = buildGraph([flow(1, "8.8.8.8")], opts({ localIps: new Set() }));
    expect(g.nodes.find((n) => n.kind === "this")?.ip).toBe("192.168.1.20");
  });

  it("separates local devices from remote hosts", () => {
    const g = buildGraph([flow(1, "192.168.1.1"), flow(2, "1.1.1.1")], opts());
    expect(g.nodes.find((n) => n.ip === "192.168.1.1")?.kind).toBe("local");
    expect(g.nodes.find((n) => n.ip === "1.1.1.1")?.kind).toBe("remote");
  });

  it("applies local-only / remote-only / threshold / protocol filters but keeps this device", () => {
    const flows = [flow(1, "192.168.1.1", { totalBytes: 50 }), flow(2, "1.1.1.1", { totalBytes: 5000, applicationProtocol: "DNS" }), flow(3, "9.9.9.9", { totalBytes: 10, applicationProtocol: "TLS" })];
    const ips = (g: ReturnType<typeof buildGraph>) => g.nodes.filter((n) => n.ip).map((n) => n.ip).sort();
    expect(ips(buildGraph(flows, opts({ localOnly: true })))).toEqual(["192.168.1.1", "192.168.1.20"]);
    expect(ips(buildGraph(flows, opts({ remoteOnly: true })))).toEqual(["1.1.1.1", "192.168.1.20", "9.9.9.9"]);
    expect(ips(buildGraph(flows, opts({ minBytes: 1000 })))).toEqual(["1.1.1.1", "192.168.1.20"]);
    expect(ips(buildGraph(flows, opts({ protocol: "DNS" })))).toEqual(["1.1.1.1", "192.168.1.20"]);
  });

  it("adds domain nodes from SNI first, then likely DNS names, linked to the host", () => {
    const g = buildGraph([flow(1, "140.82.121.4", { tls: { version: "TLS 1.3", sni: "github.com", alpnOffered: [], alpnSelected: null, cipherSuite: null, certificate: null, clientHelloAt: 1, serverHelloAt: 2, handshakeEncrypted: true }, domains: ["api.github.com"] })], opts());
    const host = g.nodes.find((n) => n.ip === "140.82.121.4")!;
    expect(host.domains).toEqual(["github.com", "api.github.com"]);
    expect(host.label).toBe("github.com");
    const dn = g.nodes.find((n) => n.kind === "domain")!;
    expect(dn.id).toBe("domain:github.com");
    expect(g.edges.some((e) => e.kind === "domain" && e.source === dn.id && e.target === host.id)).toBe(true);
  });

  it("does not attach the server's domain to the client", () => {
    const g = buildGraph([flow(1, "140.82.121.4", { domains: ["api.github.com"] })], opts());
    expect(g.nodes.find((n) => n.kind === "this")?.domains).toEqual([]);
  });

  it("clusters hosts beyond the node limit and keeps edges consistent", () => {
    const flows = Array.from({ length: 40 }, (_, i) => flow(i + 1, `20.0.0.${i + 1}`, { totalBytes: 1000 + i }));
    const g = buildGraph(flows, opts({ maxNodes: 11 }));
    const hostNodes = g.nodes.filter((n) => n.ip);
    expect(hostNodes).toHaveLength(11);
    const cluster = g.nodes.find((n) => n.kind === "cluster")!;
    expect(cluster.members).toBe(30);
    expect(g.clustered).toBe(30);
    const ids = new Set(g.nodes.map((n) => n.id));
    expect(g.edges.every((e) => ids.has(e.source) && ids.has(e.target))).toBe(true);
    const toCluster = g.edges.find((e) => e.source === cluster.id || e.target === cluster.id)!;
    expect(toCluster.flows).toBe(30);
    // the kept hosts are the busiest ones
    expect(hostNodes.some((n) => n.ip === "20.0.0.40")).toBe(true);
    expect(hostNodes.some((n) => n.ip === "20.0.0.1")).toBe(false);
  });

  it("scales node size with traffic and is empty for no flows", () => {
    const g = buildGraph([flow(1, "1.1.1.1", { totalBytes: 10_000_000 }), flow(2, "2.2.2.2", { totalBytes: 100 })], opts());
    const big = g.nodes.find((n) => n.ip === "1.1.1.1")!;
    const small = g.nodes.find((n) => n.ip === "2.2.2.2")!;
    expect(big.size).toBeGreaterThan(small.size);
    expect(buildGraph([], opts())).toEqual({ nodes: [], edges: [], clustered: 0 });
  });

  it("handles a large number of flows quickly", () => {
    const flows = Array.from({ length: 20_000 }, (_, i) => flow(i + 1, `30.${(i >> 8) & 255}.${i & 255}.1`));
    const t = performance.now();
    const g = buildGraph(flows, opts());
    expect(performance.now() - t).toBeLessThan(1500);
    expect(g.nodes.filter((n) => n.ip).length).toBe(150);
  });
});
