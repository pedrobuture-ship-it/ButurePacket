export type CaptureState = "idle" | "capturing" | "paused" | "processing" | "error";

export interface CaptureStats {
  packets: number;
  dropped: number;
  bytes: number;
  packetsPerSec: number;
  bytesPerSec: number;
  /** Bytes currently held in the in-memory buffer. */
  bufferBytes: number;
  /** 0..1 fraction of time the parser thread is busy. */
  parserLoad: number;
  durationMs: number;
}

export interface InterfaceInfo {
  name: string;
  description: string | null;
  addresses: string[];
  loopback: boolean;
  up: boolean;
}

export const EMPTY_STATS: CaptureStats = {
  packets: 0,
  dropped: 0,
  bytes: 0,
  packetsPerSec: 0,
  bytesPerSec: 0,
  bufferBytes: 0,
  parserLoad: 0,
  durationMs: 0,
};
