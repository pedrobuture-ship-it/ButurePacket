export const BYTES_PER_ROW = 16;

export function formatOffset(offset: number): string {
  return offset.toString(16).padStart(8, "0");
}

export function hexByte(b: number): string {
  return b.toString(16).padStart(2, "0");
}

export interface ByteRange {
  offset: number;
  length: number;
}

export function inRange(index: number, range: ByteRange | null): boolean {
  return range !== null && range.length > 0 && index >= range.offset && index < range.offset + range.length;
}

/** First row index touched by a range, for scrolling it into view. */
export function rowOfOffset(offset: number): number {
  return Math.floor(offset / BYTES_PER_ROW);
}
