import { create } from "zustand";
import type { OpenProgress } from "@/types/ipc";
import { EMPTY_STATS, type CaptureState, type CaptureStats, type InterfaceInfo } from "@/types/capture";

export type CaptureMode = "live" | "offline";

interface CaptureStore {
  state: CaptureState;
  mode: CaptureMode;
  interfaces: InterfaceInfo[];
  selectedInterface: string | null;
  /** Name of the opened capture file while in offline mode. */
  fileName: string | null;
  /** Set while a file is being read. */
  openProgress: OpenProgress | null;
  stats: CaptureStats;
  error: string | null;
  setState: (state: CaptureState) => void;
  setMode: (mode: CaptureMode, fileName?: string | null) => void;
  setOpenProgress: (p: OpenProgress | null) => void;
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
  fileName: null,
  openProgress: null,
  stats: EMPTY_STATS,
  error: null,
  setState: (state) => set((s) => ({ state, error: state === "error" ? s.error : null })),
  setMode: (mode, fileName = null) => set({ mode, fileName: mode === "offline" ? fileName : null }),
  setOpenProgress: (openProgress) => set({ openProgress }),
  setInterfaces: (interfaces) =>
    set((s) => ({
      interfaces,
      selectedInterface: s.selectedInterface ?? interfaces.find((i) => i.up && !i.loopback)?.name ?? interfaces[0]?.name ?? null,
    })),
  selectInterface: (selectedInterface) => set({ selectedInterface }),
  applyStats: (stats) => set({ stats }),
  fail: (error) => set({ state: "error", error }),
  reset: () => set({ state: "idle", stats: EMPTY_STATS, error: null, openProgress: null }),
}));
