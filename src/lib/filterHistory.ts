const KEY = "buturepacket.filterHistory";
const MAX = 12;

export function loadHistory(storage: Pick<Storage, "getItem"> = localStorage): string[] {
  try {
    const v = JSON.parse(storage.getItem(KEY) ?? "[]");
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, MAX) : [];
  } catch {
    return [];
  }
}

/** Newest first, no duplicates, bounded. Returns the new list. */
export function pushHistory(list: readonly string[], filter: string): string[] {
  const t = filter.trim();
  return t ? [t, ...list.filter((x) => x !== t)].slice(0, MAX) : [...list];
}

export function saveHistory(list: readonly string[], storage: Pick<Storage, "setItem"> = localStorage): void {
  try {
    storage.setItem(KEY, JSON.stringify(list));
  } catch {
    /* history just won't persist */
  }
}
