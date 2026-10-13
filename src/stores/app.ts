import { create } from "zustand";
import type { AppInfo } from "@/types/ipc";

interface AppState {
  info: AppInfo | null;
  setInfo: (info: AppInfo) => void;
}

export const useAppStore = create<AppState>((set) => ({
  info: null,
  setInfo: (info) => set({ info }),
}));
