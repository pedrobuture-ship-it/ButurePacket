import { captureActions } from "@/lib/captureActions";
import { useCaptureStore } from "@/stores/capture";
import { usePacketsStore } from "@/stores/packets";
import { useUiStore, type ViewId } from "@/stores/ui";

export type CommandSection = "Capture" | "File" | "Navigate" | "Filter" | "View" | "Help";

export interface Command {
  id: string;
  title: string;
  section: CommandSection;
  shortcut?: string;
  /** Extra words the palette also matches. */
  keywords?: string;
  enabled: () => boolean;
  run: () => void;
}

/** Views whose content responds to the global filter bar. */
export const FILTERABLE_VIEWS: ViewId[] = ["packets", "flows", "dns", "timeline", "map"];

const capture = () => useCaptureStore.getState();
const ui = () => useUiStore.getState();

const go = (view: ViewId) => () => ui().setView(view);

/** Moves keyboard focus to the filter bar, switching to a filterable view first if needed. */
export function focusFilter() {
  if (!FILTERABLE_VIEWS.includes(ui().view)) ui().setView("packets");
  // The bar mounts with the view; wait a frame.
  requestAnimationFrame(() => {
    const el = document.getElementById("global-filter") as HTMLInputElement | null;
    el?.focus();
    el?.select();
  });
}

const navigation: { view: ViewId; title: string; shortcut?: string }[] = [
  { view: "overview", title: "Go to Overview", shortcut: "Ctrl+1" },
  { view: "capture", title: "Go to Capture", shortcut: "Ctrl+2" },
  { view: "packets", title: "Go to Packets", shortcut: "Ctrl+3" },
  { view: "flows", title: "Go to Flows", shortcut: "Ctrl+4" },
  { view: "map", title: "Go to Map", shortcut: "Ctrl+5" },
  { view: "timeline", title: "Go to Timeline", shortcut: "Ctrl+6" },
  { view: "dns", title: "Go to DNS", shortcut: "Ctrl+7" },
  { view: "analytics", title: "Go to Analytics", shortcut: "Ctrl+8" },
  { view: "saved", title: "Go to Saved Captures" },
  { view: "settings", title: "Go to Settings" },
];

/** Every action in the app that has a title, and optionally a shortcut. Read by the palette and the key handler. */
export function buildCommands(): Command[] {
  const idle = () => ["idle", "error"].includes(capture().state);
  return [
    { id: "capture.start", title: "Start Capture", section: "Capture", keywords: "begin record sniff", enabled: () => idle() && capture().selectedInterface !== null, run: () => void captureActions.start() },
    { id: "capture.pause", title: "Pause Capture", section: "Capture", shortcut: "Space", enabled: () => capture().state === "capturing", run: () => void captureActions.pause() },
    { id: "capture.resume", title: "Resume Capture", section: "Capture", shortcut: "Space", enabled: () => capture().state === "paused", run: () => void captureActions.resume() },
    { id: "capture.stop", title: "Stop Capture", section: "Capture", keywords: "end", enabled: () => ["capturing", "paused"].includes(capture().state), run: () => void captureActions.stop() },
    { id: "capture.clear", title: "Clear Capture", section: "Capture", keywords: "reset empty", enabled: () => ["idle", "error"].includes(capture().state), run: () => void captureActions.clear() },
    { id: "file.open", title: "Open PCAP…", section: "File", shortcut: "Ctrl+O", keywords: "pcapng file capture import", enabled: () => idle(), run: () => void captureActions.openFile() },
    { id: "file.save", title: "Save Capture…", section: "File", keywords: "export write", enabled: () => idle() && capture().stats.packets > 0, run: () => void captureActions.save() },
    ...navigation.map((n): Command => ({ id: `nav.${n.view}`, title: n.title, section: "Navigate", shortcut: n.shortcut, keywords: n.view, enabled: () => true, run: go(n.view) })),
    { id: "filter.focus", title: "Focus Filter", section: "Filter", shortcut: "Ctrl+L", keywords: "search", enabled: () => true, run: focusFilter },
    { id: "filter.clear", title: "Clear Filters", section: "Filter", keywords: "reset remove", enabled: () => ui().filter !== "" || ui().filterDraft !== "", run: () => ui().clearFilter() },
    { id: "view.sidebar", title: "Toggle Sidebar", section: "View", shortcut: "Ctrl+B", enabled: () => true, run: () => ui().toggleSidebar() },
    { id: "view.inspector", title: "Toggle Packet Inspector", section: "View", enabled: () => ui().view === "packets", run: () => usePacketsStore.getState().setInspectorOpen(!usePacketsStore.getState().inspectorOpen) },
    { id: "help.shortcuts", title: "Show Keyboard Shortcuts", section: "Help", shortcut: "?", keywords: "help keys", enabled: () => true, run: () => ui().setShortcutsOpen(true) },
  ];
}

/** The first enabled command bound to the key combination, if any. */
export function commandForShortcut(commands: readonly Command[], matches: (shortcut: string) => boolean): Command | undefined {
  return commands.find((c) => c.shortcut && c.enabled() && matches(c.shortcut));
}
