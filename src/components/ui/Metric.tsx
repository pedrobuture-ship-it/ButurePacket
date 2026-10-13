import type { ReactNode } from "react";

interface Props {
  label: string;
  value: ReactNode;
  unit?: string;
  hint?: ReactNode;
}

export function Metric({ label, value, unit, hint }: Props) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="whitespace-nowrap text-[10px] font-medium uppercase tracking-wider text-muted">{label}</span>
      <span className="font-mono text-lg font-medium leading-none text-fg">
        {value}
        {unit && <span className="ml-1 text-xs text-muted">{unit}</span>}
      </span>
      {hint && <span className="font-mono text-[10px] text-muted">{hint}</span>}
    </div>
  );
}
