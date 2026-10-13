import { useEffect } from "react";
import { notifyError } from "@/lib/notify";

const SEEN = new Map<string, number>();
const MIN_REPEAT_MS = 5000;

/** Reports errors nobody caught as notices instead of letting them vanish silently. */
export function useGlobalErrorHandlers() {
  useEffect(() => {
    const report = (e: unknown, message: string) => {
      // Benign browser noise that is not actionable.
      if (/ResizeObserver loop/i.test(message)) return;
      const now = Date.now();
      if (now - (SEEN.get(message) ?? 0) < MIN_REPEAT_MS) return;
      SEEN.set(message, now);
      console.error(e);
      notifyError(e instanceof Error ? e : message);
    };
    const onError = (ev: ErrorEvent) => report(ev.error ?? ev.message, ev.message || "Unexpected error");
    const onRejection = (ev: PromiseRejectionEvent) => report(ev.reason, String((ev.reason as Error | undefined)?.message ?? ev.reason ?? "Unhandled error"));
    window.addEventListener("error", onError);
    window.addEventListener("unhandledrejection", onRejection);
    return () => {
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onRejection);
    };
  }, []);
}
