import { useEffect } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { useUiStore } from "@/stores/ui";

/**
 * Shows the drop overlay while a file is dragged over the window. The drop itself is handled by
 * the backend, which opens the file; the web view never receives or reports file paths.
 */
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
      .onDragDropEvent((event) => useUiStore.getState().setDragging(event.payload.type === "enter" || event.payload.type === "over"))
      .then((fn) => (unlisten = fn))
      .catch(() => undefined);
    return () => unlisten?.();
  }, []);
}
