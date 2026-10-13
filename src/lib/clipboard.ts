/** Copies text; failures (no clipboard permission) are silent because there is nothing useful to do. */
export function copyText(text: string): void {
  void navigator.clipboard?.writeText(text).catch(() => undefined);
}
