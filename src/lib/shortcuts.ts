/** Keyboard shortcut helpers. Shortcuts are written like "Ctrl+K", "Ctrl+Shift+P" or "Space". */

export interface KeyLike {
  key: string;
  ctrlKey: boolean;
  metaKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
}

const ALIASES: Record<string, string> = { " ": "space", spacebar: "space", esc: "escape" };

const normalizeKey = (k: string) => ALIASES[k.toLowerCase()] ?? k.toLowerCase();

/** True when `event` is exactly the combination in `shortcut` (Ctrl also accepts Cmd on macOS). */
export function matchShortcut(event: KeyLike, shortcut: string): boolean {
  const parts = shortcut.split("+").map((p) => p.trim());
  const key = normalizeKey(parts[parts.length - 1]);
  const mods = new Set(parts.slice(0, -1).map((m) => m.toLowerCase()));
  const wantCtrl = mods.has("ctrl") || mods.has("cmd");
  // Symbols like "?" are typed with Shift on many layouts; Shift is part of the character there.
  const symbol = key.length === 1 && !/[a-z0-9]/.test(key);
  return (
    normalizeKey(event.key) === key &&
    (event.ctrlKey || event.metaKey) === wantCtrl &&
    (symbol || event.shiftKey === mods.has("shift")) &&
    event.altKey === mods.has("alt")
  );
}

/** Display form: ["Ctrl", "K"]. */
export function shortcutKeys(shortcut: string): string[] {
  return shortcut.split("+").map((p) => (p.trim().toLowerCase() === "space" ? "Space" : p.trim().length === 1 ? p.trim().toUpperCase() : p.trim()));
}

const TEXT_ENTRY = new Set(["INPUT", "TEXTAREA", "SELECT"]);

/** Whether a plain-key shortcut (like Space) should be ignored because the user is typing or on a control. */
export function isTypingTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el || typeof el.tagName !== "string") return false;
  if (TEXT_ENTRY.has(el.tagName) || el.isContentEditable) return true;
  // Space/Enter activate buttons and menu items; don't hijack them.
  return el.tagName === "BUTTON" || ["button", "menuitem", "option", "tab"].includes(el.getAttribute("role") ?? "");
}
