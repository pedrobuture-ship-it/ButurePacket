/**
 * String interning for fields that repeat across rows (addresses, protocol names, flags).
 * A million parsed rows otherwise hold a million copies of "192.168.1.20": interning cuts the
 * per-row memory by roughly 40%. The pool is capped so hostile traffic with endless unique
 * addresses can't turn it into a leak.
 */
export class Interner {
  private readonly pool = new Map<string, string>();
  constructor(private readonly maxEntries = 200_000) {}

  get size(): number {
    return this.pool.size;
  }

  intern<T extends string | null | undefined>(value: T): T {
    if (value === null || value === undefined) return value;
    const hit = this.pool.get(value);
    if (hit !== undefined) return hit as T;
    if (this.pool.size < this.maxEntries) this.pool.set(value, value);
    return value;
  }

  clear() {
    this.pool.clear();
  }
}

/** Shares identical small arrays (e.g. TCP flag lists) between rows. */
export class ListInterner {
  private readonly pool = new Map<string, readonly string[]>();

  intern<T extends readonly string[] | null>(list: T): T {
    if (list === null) return list;
    const key = list.join(",");
    const hit = this.pool.get(key);
    if (hit) return hit as T;
    if (this.pool.size < 4096) this.pool.set(key, list);
    return list;
  }

  clear() {
    this.pool.clear();
  }
}
