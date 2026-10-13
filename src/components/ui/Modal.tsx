import type { ReactNode } from "react";
import { X } from "lucide-react";
import { IconButton } from "./IconButton";
import { OverlayPortal, useOverlay } from "./Overlay";

interface Props {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
}

export function Modal({ open, title, onClose, children, footer, width = 480 }: Props) {
  const ref = useOverlay(open, onClose);
  if (!open) return null;
  return (
    <OverlayPortal>
      <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[12vh] animate-fade-in" onMouseDown={onClose}>
        <div
          ref={ref}
          role="dialog"
          aria-modal="true"
          aria-label={title}
          tabIndex={-1}
          style={{ width }}
          className="max-w-[92vw] rounded border border-line-strong bg-surface shadow-2xl outline-none animate-pop-in"
          onMouseDown={(e) => e.stopPropagation()}
        >
          <header className="flex h-10 items-center justify-between border-b border-line px-4">
            <h2 className="text-[13px] font-semibold">{title}</h2>
            <IconButton label="Close" onClick={onClose}>
              <X size={14} />
            </IconButton>
          </header>
          <div className="selectable p-4 text-[13px]">{children}</div>
          {footer && <footer className="flex justify-end gap-2 border-t border-line px-4 py-3">{footer}</footer>}
        </div>
      </div>
    </OverlayPortal>
  );
}
