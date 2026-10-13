import { useEffect } from "react";
import { api, errorMessage, isIpcError, on } from "@/lib/api";
import { useCaptureStore } from "@/stores/capture";
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
      on("capture://stats", (s) => store.applyStats(s)),
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
