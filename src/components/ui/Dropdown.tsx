import { useEffect, useRef, useState, type ReactNode } from "react";
import { MenuList, type MenuItem } from "./Menu";

interface Props {
  trigger: (props: { open: boolean; toggle: () => void }) => ReactNode;
  items: MenuItem[];
}

export function Dropdown({ trigger, items }: Props) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", away);
    return () => window.removeEventListener("mousedown", away);
  }, [open]);
  return (
    <div ref={root} className="relative inline-block">
      {trigger({ open, toggle: () => setOpen((o) => !o) })}
      {open && (
        <div className="absolute left-0 top-full z-50 mt-1">
          <MenuList items={items} onClose={() => setOpen(false)} />
        </div>
      )}
    </div>
  );
}
