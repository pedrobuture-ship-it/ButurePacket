import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

/** Shared behaviour for Modal/Drawer: portal, Esc to close, focus trap-lite, restore focus. */
export function useOverlay(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      prev?.focus?.();
    };
  }, [open, onClose]);
  return ref;
}

export function OverlayPortal({ children }: { children: ReactNode }) {
  return createPortal(children, document.body);
}
