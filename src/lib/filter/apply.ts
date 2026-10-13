import { evaluate, type Subject } from "./evaluate";
import type { Node } from "./parser";

/** Subjects that can be pointed at an item before evaluating. */
export interface ItemSubject<T> extends Subject {
  item: T;
}

/** Items matching `ast` (all of them when there is no filter), preserving order. */
export function filterItems<T>(items: Iterable<T>, ast: Node | null, subject: ItemSubject<T>): T[] {
  if (ast === null) return Array.isArray(items) ? (items as T[]) : [...items];
  const out: T[] = [];
  for (const item of items) {
    subject.item = item;
    if (evaluate(ast, subject)) out.push(item);
  }
  return out;
}
