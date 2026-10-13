export const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

const KEY = "buturepacket.layout.";

export function loadSize(id: string, fallback: number): number {
  try {
    const raw = localStorage.getItem(KEY + id);
    const n = raw === null ? NaN : Number(raw);
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

export function saveSize(id: string, size: number): void {
  try {
    localStorage.setItem(KEY + id, String(Math.round(size)));
  } catch {
    /* storage unavailable: layout just won't persist */
  }
}
