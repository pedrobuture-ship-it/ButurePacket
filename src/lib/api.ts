import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AnalyticsSnapshot, AppInfo, OpenProgress, PacketPage, SaveResult, StorageStatus, StoredPacketQuery, DnsPayload, DnsStats, DnsTransaction, FlowView, IpcError, PacketDetail, PacketSummary, StatePayload, TimelineEvent } from "@/types/ipc";
import type { CaptureStats, InterfaceInfo } from "@/types/capture";

/** Every backend command is declared here: name → [args, result]. */
interface Commands {
  app_info: [Record<string, never>, AppInfo];
  list_capture_interfaces: [Record<string, never>, InterfaceInfo[]];
  capture_start: [{ interface: string }, void];
  capture_pause: [Record<string, never>, void];
  capture_resume: [Record<string, never>, void];
  capture_stop: [Record<string, never>, void];
  get_packet_bytes: [{ id: number }, number[]];
  clear_capture: [Record<string, never>, void];
  get_packet_detail: [{ id: number }, PacketDetail];
  get_flows: [Record<string, never>, FlowView[]];
  get_events: [Record<string, never>, TimelineEvent[]];
  get_analytics: [Record<string, never>, AnalyticsSnapshot];
  open_capture: [{ path: string }, void];
  cancel_open: [Record<string, never>, void];
  save_capture: [{ path: string }, SaveResult];
  query_stored_packets: [{ query: StoredPacketQuery }, PacketPage];
  set_persistence: [{ enabled: boolean }, void];
  get_dns: [Record<string, never>, { transactions: DnsTransaction[]; stats: DnsStats }];
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
  getPacketBytes: (id: number) => call("get_packet_bytes", { id }),
  getDns: () => call("get_dns", {}),
  openCapture: (path: string) => call("open_capture", { path }),
  cancelOpen: () => call("cancel_open", {}),
  queryStoredPackets: (query: StoredPacketQuery) => call("query_stored_packets", { query }),
  setPersistence: (enabled: boolean) => call("set_persistence", { enabled }),
  saveCapture: (path: string) => call("save_capture", { path }),
  getAnalytics: () => call("get_analytics", {}),
  getEvents: () => call("get_events", {}),
  getFlows: () => call("get_flows", {}),
  getPacketDetail: (id: number) => call("get_packet_detail", { id }),
  clearCapture: () => call("clear_capture", {}),
};
