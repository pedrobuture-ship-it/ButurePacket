import { describeError } from "@/lib/errors";
import { useNoticeStore } from "@/stores/notices";

/** Shows any failure as a consistent notice: category heading, plain message, and what to do next. */
export function notifyError(e: unknown): void {
  const d = describeError(e);
  useNoticeStore.getState().push("error", d.message, d.hint, d.title);
}
