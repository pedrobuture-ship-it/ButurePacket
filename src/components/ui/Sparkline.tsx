import { cn } from "@/lib/cn";

/** SVG path for a line through `values`, scaled into a `w`×`h` box (max value touches the top). */
export function sparklinePath(values: number[], w: number, h: number): string {
  if (values.length < 2) return "";
  const max = Math.max(...values, 1);
  const step = w / (values.length - 1);
  return values.map((v, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${(h - (v / max) * (h - 2) - 1).toFixed(1)}`).join(" ");
}

interface Props {
  values: number[];
  width?: number;
  height?: number;
  className?: string;
  label?: string;
}

export function Sparkline({ values, width = 120, height = 28, className, label }: Props) {
  const line = sparklinePath(values, width, height);
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label ?? "Activity sparkline"} className={cn("text-primary", className)}>
      {line && (
        <>
          <path d={`${line} L${width},${height} L0,${height} Z`} fill="currentColor" opacity={0.12} />
          <path d={line} fill="none" stroke="currentColor" strokeWidth={1.25} strokeLinejoin="round" />
        </>
      )}
    </svg>
  );
}
