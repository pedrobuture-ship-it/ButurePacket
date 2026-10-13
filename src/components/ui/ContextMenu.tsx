import { useEffect } from "react";
import { createPortal } from "react-dom";
import { MenuList, type MenuItem } from "./Menu";

export interface ContextMenuState {
  x: number;
  y: number;
  items: MenuItem[];
}

export function ContextMenu({ state, onClose }: { state: ContextMenuState | null; onClose: () => void }) {
  useEffect(() => {
    if (!state) return;
    const close = () => onClose();
    window.addEventListener("mousedown", close);
    window.addEventListener("blur", close);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("blur", close);
      window.removeEventListener("resize", close);
    };
  }, [state, onClose]);
  if (!state) return null;
  const x = Math.min(state.x, window.innerWidth - 220);
  const y = Math.min(state.y, window.innerHeight - state.items.length * 30 - 16);
  return createPortal(
    <div className="fixed z-[60]" style={{ left: x, top: y }} onMouseDown={(e) => e.stopPropagation()}>
      <MenuList items={state.items} onClose={onClose} />
    </div>,
    document.body,
  );
}
