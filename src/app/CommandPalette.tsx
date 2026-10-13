import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import { KeyboardShortcut } from "@/components/ui";
import { OverlayPortal, useOverlay } from "@/components/ui/Overlay";
import { cn } from "@/lib/cn";
import { buildCommands } from "@/lib/commands";
import { rankBy } from "@/lib/fuzzy";
import { shortcutKeys } from "@/lib/shortcuts";
import { useUiStore } from "@/stores/ui";

const MAX_RESULTS = 12;

export function CommandPalette() {
  const open = useUiStore((s) => s.paletteOpen);
  const setOpen = useUiStore((s) => s.setPaletteOpen);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const close = useMemo(() => () => setOpen(false), [setOpen]);
  const dialogRef = useOverlay(open, close);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const commands = useMemo(() => (open ? rankBy(buildCommands().filter((c) => c.enabled()), query, (c) => `${c.title} ${c.keywords ?? ""} ${c.section}`).slice(0, MAX_RESULTS) : []), [open, query]);

  if (!open) return null;
  const run = (i: number) => {
    const c = commands[i];
    if (!c) return;
    close();
    // Let focus return to where the user was before running the command.
    requestAnimationFrame(() => c.run());
  };

  return (
    <OverlayPortal>
      <div className="fixed inset-0 z-[70] flex items-start justify-center bg-black/60 pt-[14vh] animate-fade-in" onMouseDown={close}>
        <div ref={dialogRef} role="dialog" aria-modal="true" aria-label="Command palette" tabIndex={-1} className="w-[560px] max-w-[92vw] overflow-hidden rounded border border-line-strong bg-surface shadow-2xl outline-none focus-visible:outline-none animate-pop-in" onMouseDown={(e) => e.stopPropagation()}>
          <div className="flex items-center gap-2 border-b border-line px-3">
            <Search size={14} className="text-muted" />
            <input
              ref={inputRef}
              role="combobox"
              aria-expanded
              aria-controls="palette-list"
              aria-activedescendant={commands[active] ? `cmd-${commands[active].id}` : undefined}
              value={query}
              placeholder="Type a command…"
              spellCheck={false}
              className="h-11 flex-1 bg-transparent text-[13px] text-fg outline-none focus-visible:outline-none placeholder:text-faint"
              onChange={(e) => {
                setQuery(e.target.value);
                setActive(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown" || e.key === "ArrowUp") {
                  e.preventDefault();
                  if (commands.length) setActive((a) => (a + (e.key === "ArrowDown" ? 1 : -1) + commands.length) % commands.length);
                } else if (e.key === "Enter") {
                  e.preventDefault();
                  run(active);
                }
              }}
            />
          </div>
          <ul id="palette-list" role="listbox" className="max-h-[340px] overflow-auto py-1">
            {commands.length === 0 && <li className="px-4 py-6 text-center text-xs text-muted">No matching commands</li>}
            {commands.map((c, i) => (
              <li
                key={c.id}
                id={`cmd-${c.id}`}
                role="option"
                aria-selected={i === active}
                onMouseMove={() => setActive(i)}
                onClick={() => run(i)}
                className={cn("flex cursor-pointer items-center gap-3 px-4 py-1.5 text-[13px]", i === active ? "bg-hover text-fg" : "text-muted")}
              >
                <span className="w-16 shrink-0 text-[10px] uppercase tracking-wide text-muted">{c.section}</span>
                <span className="flex-1 text-fg">{c.title}</span>
                {c.shortcut && <KeyboardShortcut keys={shortcutKeys(c.shortcut)} />}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </OverlayPortal>
  );
}
