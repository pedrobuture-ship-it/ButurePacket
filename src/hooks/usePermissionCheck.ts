import { useEffect } from "react";
import { usePermissionStore } from "@/stores/permission";
import { useNoticeStore } from "@/stores/notices";

/** Checks capture permission once at startup and points the user to help if it is missing. */
export function usePermissionCheck() {
  useEffect(() => {
    void usePermissionStore
      .getState()
      .check()
      .then((r) => {
        if (r && r.state !== "available") useNoticeStore.getState().push("info", `Live capture is ${r.state}. Open "Capture" in the sidebar to see why and how to fix it. Opening PCAP files works regardless.`);
      });
  }, []);
}
