import { api, errorMessage } from "@/lib/api";
import { useCaptureStore } from "@/stores/capture";
import { usePacketsStore } from "@/stores/packets";

const st = () => useCaptureStore.getState();

async function run(action: () => Promise<unknown>) {
  try {
    await action();
  } catch (e) {
    st().fail(errorMessage(e));
  }
}

/** User-triggered capture operations. State changes arrive back via backend events. */
export const captureActions = {
  start: () => {
    const iface = st().selectedInterface;
    if (!iface) return;
    st().reset();
    usePacketsStore.getState().clear();
    return run(() => api.captureStart(iface));
  },
  pause: () => run(api.capturePause),
  resume: () => run(api.captureResume),
  stop: () => run(api.captureStop),
  clear: () => {
    st().reset();
    usePacketsStore.getState().clear();
    return run(api.clearCapture);
  },
  openFile: () => undefined,
  save: () => undefined,
};
