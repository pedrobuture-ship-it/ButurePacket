import type { ReactNode } from "react";
import { X } from "lucide-react";
import { IconButton } from "./IconButton";
import { OverlayPortal, useOverlay } from "./Overlay";

interface Props {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
}

export function Drawer({ open, title, onClose, children, width = 420 }: Props) {
  const ref = useOverlay(open, onClose);
  if (!open) return null;
  return (
    <OverlayPortal>
      <div className="fixed inset-0 z-50 bg-black/50 animate-fade-in" onMouseDown={onClose}>
        <aside
          ref={ref}
          role="dialog"
          aria-modal="true"
          aria-label={title}
          tabIndex={-1}
          style={{ width }}
          className="absolute inset-y-0 right-0 max-w-[92vw] border-l border-line-strong bg-surface outline-none animate-slide-in"
          onMouseDown={(e) => e.stopPropagation()}
        >
          <header className="flex h-10 items-center justify-between border-b border-line px-4">
            <h2 className="text-[13px] font-semibold">{title}</h2>
            <IconButton label="Close" onClick={onClose}>
              <X size={14} />
            </IconButton>
          </header>
          <div className="selectable h-[calc(100%-2.5rem)] overflow-auto p-4">{children}</div>
        </aside>
      </div>
    </OverlayPortal>
  );
}
