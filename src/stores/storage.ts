import { create } from "zustand";
import type { StorageStatus } from "@/types/ipc";

export const EMPTY_STORAGE: StorageStatus = { packetsWritten: 0, droppedJobs: 0, bytes: 0, limitReached: false, error: null, active: false };

interface StorageStore {
  status: StorageStatus;
  set: (s: StorageStatus) => void;
}

export const useStorageStore = create<StorageStore>((set) => ({
  status: EMPTY_STORAGE,
  set: (status) => set({ status }),
}));
