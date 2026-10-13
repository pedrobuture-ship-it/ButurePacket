import { useEffect } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { captureActions } from "@/lib/captureActions";
import { useCaptureStore } from "@/stores/capture";
import { useNoticeStore } from "@/stores/notices";
import { useUiStore } from "@/stores/ui";

/** Opens a capture file dropped onto the window. */
export function useFileDrop() {
  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
    let unlisten: (() => void) | undefined;
    let webview;
    try {
      webview = getCurrentWebview();
    } catch {
      return; // no webview handle (not running inside the desktop shell)
    }
    webview
      .onDragDropEvent((event) => {
        const ui = useUiStore.getState();
        const p = event.payload;
        if (p.type === "enter" || p.type === "over") ui.setDragging(true);
        else if (p.type === "leave") ui.setDragging(false);
        else if (p.type === "drop") {
          ui.setDragging(false);
          const busy = useCaptureStore.getState().state;
          if (busy === "capturing" || busy === "paused" || busy === "processing") {
            useNoticeStore.getState().push("warning", "Stop the current capture before opening a file.");
          } else if (p.paths[0]) void captureActions.openPath(p.paths[0]);
        }
      })
      .then((fn) => (unlisten = fn))
      .catch(() => undefined);
    return () => unlisten?.();
  }, []);
}
