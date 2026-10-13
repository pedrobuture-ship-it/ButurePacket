/**
 * Small fuzzy matcher for the command palette: every query character must appear in order.
 * Higher scores are better; `null` means no match.
 */
export function fuzzyScore(query: string, text: string): number | null {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  const t = text.toLowerCase();
  let ti = 0;
  let score = 0;
  let prev = -2;
  for (const ch of q) {
    const at = t.indexOf(ch, ti);
    if (at === -1) return null;
    // Reward consecutive hits, word starts and early matches.
    if (at === prev + 1) score += 5;
    if (at === 0 || t[at - 1] === " " || t[at - 1] === "-") score += 8;
    score += Math.max(0, 3 - at / 8);
    prev = at;
    ti = at + 1;
  }
  // An exact substring beats a scattered match.
  if (t.includes(q)) score += 20;
  // Shorter targets are tighter matches.
  return score - t.length * 0.05;
}

export function rankBy<T>(items: readonly T[], query: string, text: (item: T) => string): T[] {
  if (!query.trim()) return [...items];
  return items
    .map((item, index) => ({ item, index, score: fuzzyScore(query, text(item)) }))
    .filter((x): x is { item: T; index: number; score: number } => x.score !== null)
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .map((x) => x.item);
}
