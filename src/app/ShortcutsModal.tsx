import { Modal } from "@/components/ui";
import { KeyboardShortcut } from "@/components/ui";
import { buildCommands } from "@/lib/commands";
import { shortcutKeys } from "@/lib/shortcuts";
import { useUiStore } from "@/stores/ui";

/** Shortcuts that live inside a specific view rather than the global command registry. */
const CONTEXTUAL: { keys: string[]; label: string }[] = [
  { keys: ["Ctrl", "K"], label: "Command palette" },
  { keys: ["Esc"], label: "Close the current overlay / clear a focused filter" },
  { keys: ["J"], label: "Next packet (Packets)" },
  { keys: ["K"], label: "Previous packet (Packets)" },
  { keys: ["↑", "↓"], label: "Move selection (Packets, Flows)" },
  { keys: ["Enter"], label: "Open inspector for the selected packet" },
  { keys: ["Tab"], label: "Accept filter autocomplete suggestion" },
];

export function ShortcutsModal() {
  const open = useUiStore((s) => s.shortcutsOpen);
  const setOpen = useUiStore((s) => s.setShortcutsOpen);
  const global = buildCommands().filter((c) => c.shortcut);
  // Space is listed once even though Pause and Resume share it.
  const rows = global.filter((c, i) => global.findIndex((o) => o.shortcut === c.shortcut) === i).map((c) => ({ keys: shortcutKeys(c.shortcut!), label: c.shortcut === "Space" ? "Pause / resume capture" : c.title }));
  return (
    <Modal open={open} title="Keyboard Shortcuts" onClose={() => setOpen(false)} width={520}>
      <ul className="flex flex-col gap-1.5">
        {[...rows, ...CONTEXTUAL.filter((c) => !rows.some((r) => r.label === c.label || r.keys.join("+") === c.keys.join("+")))].map((r) => (
          <li key={r.label} className="flex items-center justify-between gap-6 text-xs">
            <span className="text-fg">{r.label}</span>
            <KeyboardShortcut keys={r.keys} />
          </li>
        ))}
      </ul>
    </Modal>
  );
}
