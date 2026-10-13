import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AnalyticsSnapshot, AppInfo, NoticePayload, OpenProgress, PacketPage, PermissionReport, RecentCapture, SaveResult, StorageStatus, StoredPacketQuery, DnsPayload, FlowView, IpcError, PacketDetail, PacketSummary, StatePayload, TimelineEvent } from "@/types/ipc";
import type { CaptureStats, InterfaceInfo } from "@/types/capture";

/** Every backend command is declared here: name → [args, result]. */
interface Commands {
  app_info: [Record<string, never>, AppInfo];
  list_capture_interfaces: [Record<string, never>, InterfaceInfo[]];
  capture_start: [{ interface: string }, void];
  capture_pause: [Record<string, never>, void];
  capture_resume: [Record<string, never>, void];
  capture_stop: [Record<string, never>, void];
  clear_capture: [Record<string, never>, void];
  get_packet_detail: [{ id: number }, PacketDetail];
  get_flow: [{ id: number }, FlowView | null];
  pick_and_open_capture: [Record<string, never>, string | null];
  pick_and_save_capture: [Record<string, never>, SaveResult | null];
  check_capture_permission: [Record<string, never>, PermissionReport];
  cancel_open: [Record<string, never>, void];
  query_stored_packets: [{ query: StoredPacketQuery }, PacketPage];
  set_persistence: [{ enabled: boolean }, void];
  list_recent_captures: [Record<string, never>, RecentCapture[]];
  open_recent_capture: [{ id: number }, void];
  forget_recent_capture: [{ id: number | null }, void];
}

/** Backend → frontend events: name → payload. */
interface Events {
  "capture://stats": CaptureStats;
  "capture://state": StatePayload;
  "capture://packets": PacketSummary[];
  "capture://flows": FlowView[];
  "capture://dns": DnsPayload;
  "capture://events": TimelineEvent[];
  "capture://analytics": AnalyticsSnapshot;
  "capture://progress": OpenProgress;
  "capture://storage": StorageStatus;
  "capture://notice": NoticePayload;
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

const inDesktopShell = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export function call<K extends keyof Commands>(cmd: K, args: Commands[K][0]): Promise<Commands[K][1]> {
  if (!inDesktopShell()) {
    return Promise.reject<Commands[K][1]>({ kind: "unavailable", message: "ButurePacket must run inside the desktop app." } satisfies IpcError);
  }
  return invoke<Commands[K][1]>(cmd, args);
}

export function on<K extends keyof Events>(event: K, handler: (payload: Events[K]) => void): Promise<UnlistenFn> {
  // Outside the desktop shell (plain browser, tests) there is no event bus.
  if (!inDesktopShell()) return Promise.resolve(() => undefined);
  return listen<Events[K]>(event, (e) => handler(e.payload));
}

export const api = {
  appInfo: () => call("app_info", {}),
  listInterfaces: () => call("list_capture_interfaces", {}),
  captureStart: (iface: string) => call("capture_start", { interface: iface }),
  capturePause: () => call("capture_pause", {}),
  captureResume: () => call("capture_resume", {}),
  captureStop: () => call("capture_stop", {}),
  /** Native file dialog + analysis; the web view never supplies a path. */
  pickAndOpenCapture: () => call("pick_and_open_capture", {}),
  pickAndSaveCapture: () => call("pick_and_save_capture", {}),
  checkCapturePermission: () => call("check_capture_permission", {}),
  cancelOpen: () => call("cancel_open", {}),
  queryStoredPackets: (query: StoredPacketQuery) => call("query_stored_packets", { query }),
  listRecentCaptures: () => call("list_recent_captures", {}),
  openRecentCapture: (id: number) => call("open_recent_capture", { id }),
  forgetRecentCapture: (id: number | null) => call("forget_recent_capture", { id }),
  setPersistence: (enabled: boolean) => call("set_persistence", { enabled }),
  getFlow: (id: number) => call("get_flow", { id }),
  getPacketDetail: (id: number) => call("get_packet_detail", { id }),
  clearCapture: () => call("clear_capture", {}),
};
