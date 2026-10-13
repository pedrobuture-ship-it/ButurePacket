import { useCaptureStore } from "@/stores/capture";

/**
 * User-triggered capture operations. The Rust capture engine is wired in
 * a later step; until then these only drive the local state machine.
 */
const st = () => useCaptureStore.getState();

export const captureActions = {
  start: () => st().setState("capturing"),
  pause: () => st().setState("paused"),
  resume: () => st().setState("capturing"),
  stop: () => st().setState("idle"),
  clear: () => st().reset(),
  openFile: () => undefined,
  save: () => undefined,
};
