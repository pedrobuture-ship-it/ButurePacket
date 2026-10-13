/** Types mirrored from the Rust side (src-tauri/src/commands). Keep in sync. */
export interface AppInfo {
  name: string;
  version: string;
  platform: string;
}

/** Error shape returned by every failing command. */
export interface IpcError {
  kind: string;
  message: string;
}

export type SessionState = "idle" | "running" | "paused" | "stopped" | "error";

export interface StatePayload {
  state: SessionState;
  error: IpcError | null;
}

/** One decoded packet row. The payload is never included; fetch bytes on demand. */
export interface PacketSummary {
  id: number;
  /** Microseconds since the Unix epoch. */
  timestamp: number;
  capturedLength: number;
  originalLength: number;
  sourceMac: string | null;
  destinationMac: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  sourcePort: number | null;
  destinationPort: number | null;
  networkProtocol: string;
  transportProtocol: string | null;
  applicationProtocol: string | null;
  tcpFlags: string[] | null;
  ttl: number | null;
  payloadLength: number;
  info: string;
  issues: string[];
}

export interface PacketField {
  name: string;
  value: string;
  /** Byte offset of the field within the frame, when it maps to wire bytes. */
  offset: number | null;
  length: number;
}

export interface PacketSection {
  id: "summary" | "frame" | "ethernet" | "network" | "transport" | "application" | "payload";
  title: string;
  offset: number | null;
  length: number;
  fields: PacketField[];
}

export interface PacketDetail {
  summary: PacketSummary;
  sections: PacketSection[];
  /** Captured bytes of the frame. */
  bytes: number[];
}
