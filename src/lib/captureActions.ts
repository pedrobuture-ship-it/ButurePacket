import { api, errorMessage, isIpcError } from "@/lib/api";
import { useUiStore } from "@/stores/ui";
import { formatCount } from "@/lib/format";
import { useAnalyticsStore } from "@/stores/analytics";
import { useCaptureStore } from "@/stores/capture";
import { useDnsStore } from "@/stores/dns";
import { useEventsStore } from "@/stores/events";
import { useFlowsStore } from "@/stores/flows";
import { useNoticeStore } from "@/stores/notices";
import { EMPTY_STORAGE, useStorageStore } from "@/stores/storage";
import { usePacketsStore } from "@/stores/packets";

const st = () => useCaptureStore.getState();
const notify = (tone: Parameters<ReturnType<typeof useNoticeStore.getState>["push"]>[0], text: string) => useNoticeStore.getState().push(tone, text);

async function run(action: () => Promise<unknown>) {
  try {
    await action();
  } catch (e) {
    st().fail(errorMessage(e));
    // Missing permission has its own screen with guidance; take the user there.
    if (isIpcError(e) && e.kind === "permissionDenied") useUiStore.getState().setView("capture");
  }
}

/** Empties every view's data (not the backend). */
export function resetViews() {
  st().reset();
  usePacketsStore.getState().clear();
  useFlowsStore.getState().clear();
  useDnsStore.getState().clear();
  useEventsStore.getState().clear();
  useAnalyticsStore.getState().reset();
  useStorageStore.getState().set(EMPTY_STORAGE);
}

/** User-triggered capture operations. State changes arrive back via backend events. */
export const captureActions = {
  start: () => {
    const iface = st().selectedInterface;
    if (!iface) return;
    resetViews();
    st().setMode("live");
    return run(() => api.captureStart(iface));
  },
  pause: () => run(api.capturePause),
  resume: () => run(api.captureResume),
  stop: () => run(api.captureStop),
  clear: () => {
    resetViews();
    st().setMode("live");
    return run(api.clearCapture);
  },
  /** The native dialog runs in the backend; views reset when the first progress event arrives. */
  openFile: async () => {
    try {
      await api.pickAndOpenCapture();
    } catch (e) {
      notify("error", errorMessage(e));
    }
  },
  cancelOpen: () => run(api.cancelOpen),
  save: async () => {
    try {
      const r = await api.pickAndSaveCapture();
      if (!r) return;
      notify(r.evicted ? "warning" : "success", r.evicted ? `Saved ${formatCount(r.packets)} packets. Older packets had already been dropped from memory and are not included.` : `Saved ${formatCount(r.packets)} packets.`);
    } catch (e) {
      notify("error", errorMessage(e));
    }
  },
};
