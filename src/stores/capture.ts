import { create } from "zustand";
import { EMPTY_STATS, type CaptureState, type CaptureStats, type InterfaceInfo } from "@/types/capture";

export type CaptureMode = "live" | "offline";

interface CaptureStore {
  state: CaptureState;
  mode: CaptureMode;
  interfaces: InterfaceInfo[];
  selectedInterface: string | null;
  stats: CaptureStats;
  error: string | null;
  setState: (state: CaptureState) => void;
  setMode: (mode: CaptureMode) => void;
  setInterfaces: (list: InterfaceInfo[]) => void;
  selectInterface: (name: string) => void;
  applyStats: (stats: CaptureStats) => void;
  fail: (message: string) => void;
  reset: () => void;
}

export const useCaptureStore = create<CaptureStore>((set) => ({
  state: "idle",
  mode: "live",
  interfaces: [],
  selectedInterface: null,
  stats: EMPTY_STATS,
  error: null,
  setState: (state) => set({ state, error: state === "error" ? undefined : null }),
  setMode: (mode) => set({ mode }),
  setInterfaces: (interfaces) =>
    set((s) => ({
      interfaces,
      selectedInterface: s.selectedInterface ?? interfaces.find((i) => i.up && !i.loopback)?.name ?? interfaces[0]?.name ?? null,
    })),
  selectInterface: (selectedInterface) => set({ selectedInterface }),
  applyStats: (stats) => set({ stats }),
  fail: (error) => set({ state: "error", error }),
  reset: () => set({ state: "idle", stats: EMPTY_STATS, error: null }),
}));
