import { useEffect } from "react";
import { buildCommands, commandForShortcut } from "@/lib/commands";
import { isTypingTarget, matchShortcut } from "@/lib/shortcuts";
import { useUiStore } from "@/stores/ui";

/** Application-wide keyboard shortcuts. Plain keys never fire while the user is typing or on a control. */
export function useGlobalShortcuts() {
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const ui = useUiStore.getState();
      if (matchShortcut(e, "Ctrl+K") || matchShortcut(e, "Ctrl+Shift+P")) {
        e.preventDefault();
        ui.setPaletteOpen(!ui.paletteOpen);
        return;
      }
      if (ui.paletteOpen || ui.shortcutsOpen) return; // overlays own the keyboard while open
      const plain = !(e.ctrlKey || e.metaKey || e.altKey);
      if (plain && isTypingTarget(e.target)) return;
      const command = commandForShortcut(buildCommands(), (s) => matchShortcut(e, s));
      if (!command) return;
      e.preventDefault();
      command.run();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}
