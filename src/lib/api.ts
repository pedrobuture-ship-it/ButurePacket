import { invoke } from "@tauri-apps/api/core";
import type { AppInfo } from "@/types/ipc";

/** Every backend command is declared here: name → [args, result]. */
interface Commands {
  app_info: [Record<string, never>, AppInfo];
}

export function call<K extends keyof Commands>(cmd: K, args: Commands[K][0]): Promise<Commands[K][1]> {
  return invoke<Commands[K][1]>(cmd, args);
}

export const api = {
  appInfo: () => call("app_info", {}),
};
