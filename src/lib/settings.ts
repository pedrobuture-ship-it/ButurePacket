const PERSIST_KEY = "buturepacket.persistCaptures";

/** Whether captures are stored in the local database while they are analysed (default: yes). */
export function loadPersistSetting(): boolean {
  try {
    return localStorage.getItem(PERSIST_KEY) !== "0";
  } catch {
    return true;
  }
}

export function savePersistSetting(enabled: boolean): void {
  try {
    localStorage.setItem(PERSIST_KEY, enabled ? "1" : "0");
  } catch {
    /* settings just won't survive a restart */
  }
}

/** Removes every saved panel size and the sidebar state. Returns how many entries were removed. */
export function resetLayout(storage: Pick<Storage, "length" | "key" | "removeItem"> = localStorage): number {
  const keys: string[] = [];
  for (let i = 0; i < storage.length; i++) {
    const k = storage.key(i);
    if (k && (k.startsWith("buturepacket.layout.") || k === "buturepacket.sidebarCollapsed")) keys.push(k);
  }
  keys.forEach((k) => storage.removeItem(k));
  return keys.length;
}
