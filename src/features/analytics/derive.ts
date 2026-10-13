import type { MetricBucket, TcpTotals } from "@/types/ipc";

export type SeriesKey = "packets" | "bytes" | "newFlows" | "activeFlows";

/** Values of one metric for the newest `n` seconds, oldest first, padded with zeros on the left. */
export function seriesValues(series: readonly MetricBucket[], key: SeriesKey, n = 60): number[] {
  const tail = series.slice(-n).map((b) => b[key]);
  return [...new Array<number>(Math.max(0, n - tail.length)).fill(0), ...tail];
}

/**
 * Current per-second rate: the mean of the last few *completed* seconds. The newest bucket is
 * still filling, so including it would make the headline number flicker low.
 */
export function currentRate(series: readonly MetricBucket[], key: SeriesKey, window = 3): number {
  if (series.length === 0) return 0;
  const done = series.length > 1 ? series.slice(0, -1) : series;
  const recent = done.slice(-window);
  return recent.reduce((sum, b) => sum + b[key], 0) / recent.length;
}

/** Latest value of a gauge-like metric (active flows). */
export function latest(series: readonly MetricBucket[], key: SeriesKey): number {
  return series.length ? series[series.length - 1][key] : 0;
}

export interface TcpHealth {
  retransmissionRate: number;
  resetRate: number;
}

/** Fractions (0..1) of TCP packets that were retransmissions / carried RST. */
export function tcpHealth(tcp: TcpTotals): TcpHealth {
  return tcp.packets > 0 ? { retransmissionRate: tcp.retransmissions / tcp.packets, resetRate: tcp.resets / tcp.packets } : { retransmissionRate: 0, resetRate: 0 };
}

/** Bar widths (0..1) relative to the largest entry. */
export function barFractions(values: readonly number[]): number[] {
  const max = Math.max(0, ...values);
  return values.map((v) => (max > 0 ? v / max : 0));
}
