import { useEffect } from "react";
import { api, errorMessage, on } from "@/lib/api";
import { useCaptureStore } from "@/stores/capture";
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
      on("capture://state", ({ state, error }) => {
        if (error) store.fail(error.message);
        else store.setState(mapState[state]);
      }),
    ];
    api
      .listInterfaces()
      .then(store.setInterfaces)
      .catch((e) => store.fail(errorMessage(e)));
    return () => {
      unlisten.forEach((p) => p.then((f) => f()).catch(() => undefined));
    };
  }, []);
}
