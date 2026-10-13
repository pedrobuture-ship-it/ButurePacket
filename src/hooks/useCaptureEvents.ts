import { useEffect } from "react";
import { api, errorMessage, isIpcError, on } from "@/lib/api";
import { useCaptureStore } from "@/stores/capture";
import { formatCount } from "@/lib/format";
import { useNoticeStore } from "@/stores/notices";
import { useStorageStore } from "@/stores/storage";
import { resetViews } from "@/lib/captureActions";
import { notifyError } from "@/lib/notify";
import { useAnalyticsStore } from "@/stores/analytics";
import { useDnsStore } from "@/stores/dns";
import { useEventsStore } from "@/stores/events";
import { useFlowsStore } from "@/stores/flows";
import { usePacketsStore } from "@/stores/packets";
import type { SessionState } from "@/types/ipc";
import type { CaptureState } from "@/types/capture";

const mapState: Record<SessionState, CaptureState> = {
  idle: "idle",
  running: "capturing",
  paused: "paused",
  stopped: "idle",
  error: "error",
};

/** Loads interfaces once and keeps the capture store in sync with backend events. */
export function useCaptureEvents() {
  useEffect(() => {
    const store = useCaptureStore.getState();
    const unlisten: Promise<() => void>[] = [
      on("capture://stats", (s) => {
        // First drops of a session: the buffer between capture and analysis is full or the kernel overflowed.
        if (s.dropped > 0 && useCaptureStore.getState().stats.dropped === 0) {
          useNoticeStore.getState().push("warning", "Packets are being dropped because the capture cannot keep up with the traffic.", "Close busy applications, capture on a less busy interface, or stop and review what was captured so far.", "Memory limit");
        }
        store.applyStats(s);
      }),
      on("capture://notice", (n) => useNoticeStore.getState().push(n.tone, n.text)),
      on("capture://storage", (s) => {
        const notify = useNoticeStore.getState().push;
        const prev = useStorageStore.getState().status;
        useStorageStore.getState().set(s);
        if (s.error && s.error !== prev.error) notifyError({ kind: "storage", message: `Could not store this capture on disk: ${s.error}`, hint: "The capture keeps working; it just will not be saved to the capture database." });
        else if (s.limitReached && !prev.limitReached) notify("warning", "The capture database reached its size limit. New packets are still analysed live but are no longer stored.");
        else if (s.droppedJobs > 0 && prev.droppedJobs === 0) notify("warning", "Storage cannot keep up with the packet rate; some packets are not being stored.");
      }),
      on("capture://progress", (p) => {
        const notify = useNoticeStore.getState().push;
        if (!p.done) {
          if (store.openProgress === null && useCaptureStore.getState().openProgress === null) {
            // First event of a new file: start from a clean slate in offline mode.
            resetViews();
            store.setMode("offline", p.fileName);
          }
          store.setState("processing");
          store.setOpenProgress(p);
          return;
        }
        store.setOpenProgress(null);
        if (p.error) {
          store.setMode("live");
          store.setState("idle");
          notifyError(p.error);
          return;
        }
        store.setState("idle");
        if (p.cancelled) notify("info", "Opening was cancelled. Showing what was read so far.");
        if (p.truncatedTail) notify("warning", "The file ends in the middle of a packet. Everything before that was loaded.");
        if (p.skipped > 0) notify("warning", `${formatCount(p.skipped)} packets were skipped (unsupported or inconsistent).`);
        if (p.rowsTruncated) notify("warning", "Large capture: the packet list shows the first 1,000,000 packets. Flows, DNS, timeline and analytics cover the whole file.");
      }),
      on("capture://analytics", (a) => useAnalyticsStore.getState().set(a)),
      on("capture://events", (evs) => useEventsStore.getState().append(evs)),
      on("capture://dns", (p) => useDnsStore.getState().apply(p)),
      on("capture://flows", (flows) => useFlowsStore.getState().upsert(flows)),
      on("capture://packets", (batch) => usePacketsStore.getState().append(batch)),
      on("capture://state", ({ state, error }) => {
        if (error) store.fail(error.message);
        else store.setState(mapState[state]);
      }),
    ];
    api
      .listInterfaces()
      .then(store.setInterfaces)
      .catch((e) => {
        // Plain-browser dev sessions have no backend; that is not a user-facing failure.
        if (!(isIpcError(e) && e.kind === "unavailable")) store.fail(errorMessage(e));
      });
    return () => {
      unlisten.forEach((p) => p.then((f) => f()).catch(() => undefined));
    };
  }, []);
}
