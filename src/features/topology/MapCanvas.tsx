import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetJson } from "cytoscape";
import type { Graph, GraphNode, NodeKind } from "./graph";

export interface Selection {
  type: "node" | "edge";
  id: string;
}

const COLORS = {
  line: "#24503e",
  lineActive: "#58e38c",
  text: "#d8e7de",
  muted: "#70877a",
  bg: "#07100d",
  surface: "#102019",
  primary: "#58e38c",
  primaryMuted: "#2e8f58",
  info: "#5aa9e0",
  warning: "#d9a548",
};

const STYLE: StylesheetJson = [
  { selector: "node", style: { width: "data(size)", height: "data(size)", "background-color": COLORS.surface, "border-width": 1.5, "border-color": COLORS.primaryMuted, label: "data(label)", color: COLORS.text, "font-family": "JetBrains Mono, monospace", "font-size": 9, "text-valign": "bottom", "text-margin-y": 4, "min-zoomed-font-size": 7, "text-wrap": "ellipsis", "text-max-width": "110px" } },
  { selector: 'node[kind = "this"]', style: { "background-color": "#14271f", "border-color": COLORS.primary, "border-width": 2.5, color: COLORS.primary } },
  { selector: 'node[kind = "local"]', style: { "border-color": COLORS.primaryMuted } },
  { selector: 'node[kind = "remote"]', style: { "border-color": COLORS.info } },
  { selector: 'node[kind = "domain"]', style: { shape: "diamond", "border-color": COLORS.warning, "background-color": "#2a2314", color: COLORS.warning } },
  { selector: 'node[kind = "cluster"]', style: { shape: "round-rectangle", "border-style": "dashed", "border-color": COLORS.muted, color: COLORS.muted } },
  { selector: "edge", style: { width: "mapData(weight, 0, 1, 1, 4)", "line-color": COLORS.line, "curve-style": "bezier", opacity: 0.75 } },
  { selector: 'edge[kind = "domain"]', style: { width: 1, "line-style": "dashed", "line-color": "#4a4126", opacity: 0.6 } },
  { selector: "edge.active", style: { "line-color": COLORS.lineActive, opacity: 1 } },
  { selector: ":selected", style: { "border-color": "#ffffff", "border-width": 3, "line-color": "#ffffff", opacity: 1 } },
];

const LEVEL: Record<NodeKind, number> = { this: 4, local: 3, remote: 2, cluster: 1, domain: 0 };
const ACTIVE_WINDOW_MICROS = 2_000_000;
const LAYOUT_MIN_INTERVAL_MS = 1500;
const MAX_FIT_ZOOM = 1.25;

function toElements(graph: Graph): ElementDefinition[] {
  const maxBytes = Math.max(1, ...graph.edges.map((e) => e.bytes));
  const newest = Math.max(0, ...graph.edges.map((e) => e.lastSeenAt));
  const nodes = graph.nodes.map((n: GraphNode) => ({ group: "nodes" as const, data: { id: n.id, kind: n.kind, label: n.label, size: n.size } }));
  const edges = graph.edges.map((e) => ({
    group: "edges" as const,
    data: { id: e.id, source: e.source, target: e.target, kind: e.kind, weight: Math.log10(e.bytes + 1) / Math.log10(maxBytes + 1) },
    classes: e.kind === "flow" && newest - e.lastSeenAt <= ACTIVE_WINDOW_MICROS ? "active" : "",
  }));
  return [...nodes, ...edges];
}

/** Domains sit just outside the host they were learned from, instead of on their own ring. */
function placeDomainsNextToHosts(cy: Core) {
  const center = cy.nodes('[kind = "this"]').first();
  const origin = center.nonempty() ? center.position() : { x: 0, y: 0 };
  cy.nodes('[kind = "domain"]').forEach((d) => {
    const host = d.neighborhood('node[kind != "domain"]').nodes().first();
    if (host.empty()) return;
    const p = host.position();
    const dx = p.x - origin.x;
    const dy = p.y - origin.y;
    const len = Math.hypot(dx, dy) || 1;
    const gap = Number(host.data("size")) / 2 + 26;
    d.position({ x: p.x + (dx / len) * gap, y: p.y + (dy / len) * gap });
  });
}

interface Props {
  graph: Graph;
  selected: Selection | null;
  onSelect: (s: Selection | null) => void;
}

export function MapCanvas({ graph, selected, onSelect }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const lastLayout = useRef(0);
  const structure = useRef("");
  const userMoved = useRef(false);
  const onSelectRef = useRef(onSelect);
  useEffect(() => {
    onSelectRef.current = onSelect;
  }, [onSelect]);

  useEffect(() => {
    const cy = cytoscape({ container: host.current, style: STYLE, minZoom: 0.15, maxZoom: 3, wheelSensitivity: 0.25, boxSelectionEnabled: false });
    cyRef.current = cy;
    // A fresh Cytoscape instance has no positions yet (also true after a StrictMode remount).
    structure.current = "";
    userMoved.current = false;
    cy.on("tap", (e) => {
      if (e.target === cy) onSelectRef.current(null);
      else onSelectRef.current({ type: e.target.isNode() ? "node" : "edge", id: e.target.id() });
    });
    // Keep the canvas in sync with its container (panel resizes, first layout pass).
    const observer = new ResizeObserver(() => {
      cy.resize();
      if (!userMoved.current) {
        cy.fit(undefined, 36);
        if (cy.zoom() > MAX_FIT_ZOOM) {
          cy.zoom(MAX_FIT_ZOOM);
          cy.center();
        }
      }
    });
    if (host.current) observer.observe(host.current);
    cy.on("zoom pan", () => {
      if (cy.scratch("_fitting")) return;
      userMoved.current = true;
    });
    return () => {
      observer.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // Sync data in place; only re-run the layout when the set of nodes changes (and not too often).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const elements = toElements(graph);
    const wanted = new Map(elements.map((e) => [e.data.id as string, e]));
    cy.batch(() => {
      cy.elements().forEach((el) => {
        if (!wanted.has(el.id())) el.remove();
      });
      for (const [id, def] of wanted) {
        const existing = cy.getElementById(id);
        if (existing.empty()) cy.add(def);
        else {
          existing.data(def.data);
          existing.classes(def.classes ?? "");
        }
      }
    });
    const signature = graph.nodes.map((n) => n.id).sort().join("|");
    const first = structure.current === "";
    if (signature !== structure.current && (first || Date.now() - lastLayout.current > LAYOUT_MIN_INTERVAL_MS)) {
      structure.current = signature;
      lastLayout.current = Date.now();
      cy.scratch("_fitting", true);
      cy.resize();
      cy.layout({ name: "concentric", concentric: (n) => LEVEL[n.data("kind") as NodeKind] ?? 0, levelWidth: () => 1, minNodeSpacing: 28, animate: false, fit: !userMoved.current, padding: 36 }).run();
      placeDomainsNextToHosts(cy);
      if (first || !userMoved.current) {
        cy.fit(undefined, 36);
        // A handful of nodes would otherwise be blown up to fill the whole canvas.
        if (cy.zoom() > MAX_FIT_ZOOM) {
          cy.zoom(MAX_FIT_ZOOM);
          cy.center();
        }
      }
      cy.scratch("_fitting", false);
    }
  }, [graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements(":selected").unselect();
    if (selected) cy.getElementById(selected.id).select();
  }, [selected, graph]);

  return (
    <div
      ref={host}
      role="img"
      aria-label="Network map"
      className="h-full w-full"
      style={{
        backgroundColor: COLORS.bg,
        backgroundImage: "linear-gradient(rgba(36,80,62,0.22) 1px, transparent 1px), linear-gradient(90deg, rgba(36,80,62,0.22) 1px, transparent 1px)",
        backgroundSize: "32px 32px",
      }}
    />
  );
}
