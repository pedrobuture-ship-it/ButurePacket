import { create } from "zustand";

export type ViewId = "overview" | "capture" | "packets" | "flows" | "map" | "timeline" | "dns" | "analytics" | "saved" | "settings";

interface UiStore {
  view: ViewId;
  sidebarCollapsed: boolean;
  /** Text typed in the global filter bar. */
  filterDraft: string;
  /** Filter text currently applied to every view. */
  filter: string;
  setView: (view: ViewId) => void;
  toggleSidebar: () => void;
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
  view: "packets",
  sidebarCollapsed: readCollapsed(),
  filterDraft: "",
  filter: "",
  setView: (view) => set({ view }),
  toggleSidebar: () => {
    const next = !get().sidebarCollapsed;
    try {
      localStorage.setItem(collapsedKey, next ? "1" : "0");
    } catch {
      /* ignore */
    }
    set({ sidebarCollapsed: next });
  },
  setFilterDraft: (filterDraft) => set({ filterDraft }),
  applyFilter: (text) => set((s) => ({ filter: (text ?? s.filterDraft).trim(), filterDraft: (text ?? s.filterDraft).trim() })),
  clearFilter: () => set({ filter: "", filterDraft: "" }),
}));
