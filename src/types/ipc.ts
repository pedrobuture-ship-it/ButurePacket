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

export interface BatchPayload {
  count: number;
  firstId: number;
  lastId: number;
}
