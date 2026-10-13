export function KeyboardShortcut({ keys }: { keys: string[] }) {
  return (
    <span className="inline-flex items-center gap-1">
      {keys.map((k) => (
        <kbd key={k} className="rounded-sm border border-line-strong bg-raised px-1 font-mono text-[10px] leading-4 text-muted">
          {k}
        </kbd>
      ))}
    </span>
  );
}
