import { create } from "zustand";
import { parseFilter, type Node } from "@/lib/filter";

export type ViewId = "overview" | "capture" | "packets" | "flows" | "map" | "timeline" | "dns" | "analytics" | "saved" | "settings";

interface UiStore {
  view: ViewId;
  sidebarCollapsed: boolean;
  /** A file is being dragged over the window. */
  dragging: boolean;
  paletteOpen: boolean;
  shortcutsOpen: boolean;
  /** Text typed in the global filter bar. */
  filterDraft: string;
  /** Filter text currently applied to every view. */
  filter: string;
  /** Parsed form of `filter` (null = match everything). */
  filterAst: Node | null;
  /** Why the last attempt to apply a filter failed, if it did. */
  filterError: string | null;
  setView: (view: ViewId) => void;
  toggleSidebar: () => void;
  setDragging: (dragging: boolean) => void;
  setPaletteOpen: (open: boolean) => void;
  setShortcutsOpen: (open: boolean) => void;
  setFilterDraft: (text: string) => void;
  applyFilter: (text?: string) => void;
  clearFilter: () => void;
}

const collapsedKey = "buturepacket.sidebarCollapsed";
const readCollapsed = () => {
  try {
    return localStorage.getItem(collapsedKey) === "1";
  } catch {
    return false;
  }
};

export const useUiStore = create<UiStore>((set, get) => ({
  view: "overview",
  sidebarCollapsed: readCollapsed(),
  dragging: false,
  paletteOpen: false,
  shortcutsOpen: false,
  filterDraft: "",
  filter: "",
  filterAst: null,
  filterError: null,
  setView: (view) => set({ view }),
  setDragging: (dragging) => set({ dragging }),
  setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
  setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),
  toggleSidebar: () => {
    const next = !get().sidebarCollapsed;
    try {
      localStorage.setItem(collapsedKey, next ? "1" : "0");
    } catch {
      /* ignore */
    }
    set({ sidebarCollapsed: next });
  },
  setFilterDraft: (filterDraft) => set({ filterDraft, filterError: null }),
  applyFilter: (text) =>
    set((s) => {
      const t = (text ?? s.filterDraft).trim();
      const r = parseFilter(t);
      if (!r.ok) return { filterDraft: t, filterError: r.error.message };
      return { filter: t, filterDraft: t, filterAst: r.ast, filterError: null };
    }),
  clearFilter: () => set({ filter: "", filterDraft: "", filterAst: null, filterError: null }),
}));
