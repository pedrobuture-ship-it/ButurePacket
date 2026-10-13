import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AppInfo, BatchPayload, IpcError, StatePayload } from "@/types/ipc";
import type { CaptureStats, InterfaceInfo } from "@/types/capture";

/** Every backend command is declared here: name → [args, result]. */
interface Commands {
  app_info: [Record<string, never>, AppInfo];
  list_capture_interfaces: [Record<string, never>, InterfaceInfo[]];
  capture_start: [{ interface: string }, void];
  capture_pause: [Record<string, never>, void];
  capture_resume: [Record<string, never>, void];
  capture_stop: [Record<string, never>, void];
}

/** Backend → frontend events: name → payload. */
interface Events {
  "capture://stats": CaptureStats;
  "capture://state": StatePayload;
  "capture://batch": BatchPayload;
}

export function isIpcError(e: unknown): e is IpcError {
  return typeof e === "object" && e !== null && "kind" in e && "message" in e;
}

/** Normalises anything thrown by `invoke` into a user-presentable message. */
export function errorMessage(e: unknown): string {
  if (isIpcError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return typeof e === "string" ? e : "Unexpected error.";
}

export function call<K extends keyof Commands>(cmd: K, args: Commands[K][0]): Promise<Commands[K][1]> {
  return invoke<Commands[K][1]>(cmd, args);
}

export function on<K extends keyof Events>(event: K, handler: (payload: Events[K]) => void): Promise<UnlistenFn> {
  return listen<Events[K]>(event, (e) => handler(e.payload));
}

export const api = {
  appInfo: () => call("app_info", {}),
  listInterfaces: () => call("list_capture_interfaces", {}),
  captureStart: (iface: string) => call("capture_start", { interface: iface }),
  capturePause: () => call("capture_pause", {}),
  captureResume: () => call("capture_resume", {}),
  captureStop: () => call("capture_stop", {}),
};
