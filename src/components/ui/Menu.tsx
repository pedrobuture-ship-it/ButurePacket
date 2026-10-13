import { useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { KeyboardShortcut } from "./KeyboardShortcut";

export interface MenuItem {
  id: string;
  label: string;
  icon?: ReactNode;
  shortcut?: string[];
  danger?: boolean;
  disabled?: boolean;
  separator?: boolean;
  onSelect?: () => void;
}

/** Keyboard-navigable list of actions, shared by Dropdown and ContextMenu. */
export function MenuList({ items, onClose, className }: { items: MenuItem[]; onClose: () => void; className?: string }) {
  const actionable = items.filter((i) => !i.separator && !i.disabled);
  const [active, setActive] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => ref.current?.focus(), []);

  const choose = (item?: MenuItem) => {
    if (!item) return;
    onClose();
    item.onSelect?.();
  };

  return (
    <div
      ref={ref}
      role="menu"
      tabIndex={-1}
      className={cn("min-w-48 rounded border border-line-strong bg-raised py-1 shadow-xl outline-none animate-pop-in", className)}
      onKeyDown={(e) => {
        if (e.key === "ArrowDown") setActive((a) => (a + 1) % actionable.length);
        else if (e.key === "ArrowUp") setActive((a) => (a - 1 + actionable.length) % actionable.length);
        else if (e.key === "Enter") choose(actionable[active]);
        else if (e.key === "Escape") onClose();
        else return;
        e.preventDefault();
        e.stopPropagation();
      }}
    >
      {items.map((item) =>
        item.separator ? (
          <div key={item.id} role="separator" className="my-1 h-px bg-line" />
        ) : (
          <button
            key={item.id}
            role="menuitem"
            type="button"
            disabled={item.disabled}
            onMouseEnter={() => setActive(actionable.indexOf(item))}
            onClick={() => choose(item)}
            className={cn(
              "flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs disabled:opacity-40",
              item.danger ? "text-danger" : "text-fg",
              actionable[active] === item && "bg-hover",
            )}
          >
            <span className="w-4 text-muted">{item.icon}</span>
            <span className="flex-1">{item.label}</span>
            {item.shortcut && <KeyboardShortcut keys={item.shortcut} />}
          </button>
        ),
      )}
    </div>
  );
}
