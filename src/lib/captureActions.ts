import { open, save } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "@/lib/api";
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
  }
}

/** Empties every view's data (not the backend). */
function resetViews() {
  st().reset();
  usePacketsStore.getState().clear();
  useFlowsStore.getState().clear();
  useDnsStore.getState().clear();
  useEventsStore.getState().clear();
  useAnalyticsStore.getState().reset();
  useStorageStore.getState().set(EMPTY_STORAGE);
}

const CAPTURE_FILTERS = [{ name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] }];

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
  /** Opens a capture file by path (from the dialog or a drag-and-drop). */
  openPath: async (path: string) => {
    resetViews();
    st().setMode("offline", path.split(/[\\/]/).pop() ?? path);
    try {
      await api.openCapture(path);
    } catch (e) {
      st().setMode("live");
      notify("error", errorMessage(e));
    }
  },
  openFile: async () => {
    try {
      const picked = await open({ multiple: false, directory: false, filters: CAPTURE_FILTERS });
      if (typeof picked === "string") await captureActions.openPath(picked);
    } catch (e) {
      notify("error", errorMessage(e));
    }
  },
  cancelOpen: () => run(api.cancelOpen),
  save: async () => {
    try {
      const path = await save({ defaultPath: "capture.pcap", filters: [{ name: "PCAP", extensions: ["pcap"] }] });
      if (!path) return;
      const r = await api.saveCapture(path);
      notify(r.evicted ? "warning" : "success", r.evicted ? `Saved ${formatCount(r.packets)} packets. Older packets had already been dropped from memory and are not included.` : `Saved ${formatCount(r.packets)} packets.`);
    } catch (e) {
      notify("error", errorMessage(e));
    }
  },
};
