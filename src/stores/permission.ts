import { create } from "zustand";
import { api, errorMessage } from "@/lib/api";
import type { PermissionReport } from "@/types/ipc";

interface PermissionStore {
  report: PermissionReport | null;
  checking: boolean;
  error: string | null;
  check: () => Promise<PermissionReport | null>;
}

export const usePermissionStore = create<PermissionStore>((set) => ({
  report: null,
  checking: false,
  error: null,
  check: async () => {
    set({ checking: true, error: null });
    try {
      const report = await api.checkCapturePermission();
      set({ report, checking: false });
      return report;
    } catch (e) {
      set({ checking: false, error: errorMessage(e) });
      return null;
    }
  },
}));
