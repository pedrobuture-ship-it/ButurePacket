import { FilterError } from "@/lib/filter";
import { isIpcError } from "@/lib/api";
import { sanitizeText } from "@/lib/sanitize";

export type ErrorCategory = "permission" | "capture" | "file" | "corrupt-capture" | "disk" | "memory" | "filter" | "parser" | "unavailable" | "internal";

/** A failure described the same way everywhere: what kind, what happened, what to do. */
export interface AppError {
  category: ErrorCategory;
  /** Short heading, e.g. "Permission error". */
  title: string;
  message: string;
  hint?: string;
}

const TITLES: Record<ErrorCategory, string> = {
  permission: "Permission error",
  capture: "Capture error",
  file: "File error",
  "corrupt-capture": "Unreadable capture",
  disk: "Disk error",
  memory: "Memory limit",
  filter: "Invalid filter",
  parser: "Parser error",
  unavailable: "Not available here",
  internal: "Unexpected error",
};

const CATEGORY_BY_KIND: Record<string, ErrorCategory> = {
  permissionDenied: "permission",
  interfaceNotFound: "capture",
  alreadyRunning: "capture",
  notRunning: "capture",
  busy: "capture",
  backend: "capture",
  invalidCaptureFile: "corrupt-capture",
  io: "file",
  storage: "disk",
  packetNotFound: "memory",
  unavailable: "unavailable",
};

export function categoryTitle(c: ErrorCategory): string {
  return TITLES[c];
}

/** Turns anything thrown (backend IPC errors, filter errors, plain errors) into an `AppError`. Never throws. */
export function describeError(e: unknown): AppError {
  if (isIpcError(e)) {
    const category = CATEGORY_BY_KIND[e.kind] ?? "internal";
    return { category, title: TITLES[category], message: sanitizeText(e.message), hint: e.hint ? sanitizeText(e.hint) : undefined };
  }
  if (e instanceof FilterError) {
    return { category: "filter", title: TITLES.filter, message: sanitizeText(e.message), hint: "Check the filter syntax; press Tab in the filter bar for suggestions." };
  }
  if (e instanceof Error) {
    return { category: "internal", title: TITLES.internal, message: sanitizeText(e.message || "Something went wrong.") };
  }
  if (typeof e === "string" && e) return { category: "internal", title: TITLES.internal, message: sanitizeText(e) };
  return { category: "internal", title: TITLES.internal, message: "Something went wrong." };
}
