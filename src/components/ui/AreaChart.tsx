import { useId, useState } from "react";

export interface AreaSeries {
  label: string;
  values: number[];
  /** CSS colour (a token like `var(--color-primary)`). */
  color: string;
}

interface Props {
  series: AreaSeries[];
  height?: number;
  formatValue: (v: number) => string;
  /** Label for the first and last sample, shown under the chart. */
  startLabel?: string;
  endLabel?: string;
}

const W = 600; // viewBox width; the SVG scales to its container
const PAD = 2;

/** Polyline points for `values` scaled into a W×H box with the shared maximum at the top. */
export function areaPoints(values: number[], max: number, h: number): string {
  if (values.length < 2) return "";
  const step = W / (values.length - 1);
  return values.map((v, i) => `${(i * step).toFixed(1)},${(h - PAD - (max > 0 ? (v / max) * (h - PAD * 2) : 0)).toFixed(1)}`).join(" ");
}

export function AreaChart({ series, height = 140, formatValue, startLabel, endLabel }: Props) {
  const id = useId();
  const [hover, setHover] = useState<number | null>(null);
  const n = Math.max(0, ...series.map((s) => s.values.length));
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const index = hover !== null && n > 1 ? Math.min(n - 1, Math.max(0, hover)) : null;
  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${W} ${height}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={series.map((s) => s.label).join(" and ")}
        className="block w-full"
        style={{ height }}
        onPointerMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          setHover(Math.round(((e.clientX - r.left) / r.width) * (n - 1)));
        }}
        onPointerLeave={() => setHover(null)}
      >
        {[0.25, 0.5, 0.75].map((f) => (
          <line key={f} x1={0} x2={W} y1={height * f} y2={height * f} stroke="var(--color-line)" strokeWidth={1} vectorEffect="non-scaling-stroke" opacity={0.6} />
        ))}
        {series.map((s, i) => {
          const pts = areaPoints(s.values, max, height);
          if (!pts) return null;
          return (
            <g key={s.label}>
              <defs>
                <linearGradient id={`${id}-${i}`} x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor={s.color} stopOpacity={0.28} />
                  <stop offset="100%" stopColor={s.color} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <polygon points={`0,${height} ${pts} ${W},${height}`} fill={`url(#${id}-${i})`} />
              <polyline points={pts} fill="none" stroke={s.color} strokeWidth={1.5} strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
            </g>
          );
        })}
        {index !== null && <line x1={(index / (n - 1)) * W} x2={(index / (n - 1)) * W} y1={0} y2={height} stroke="var(--color-muted)" strokeWidth={1} vectorEffect="non-scaling-stroke" strokeDasharray="3 3" />}
      </svg>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-faint">
        <span>{startLabel}</span>
        <span>peak {formatValue(max)}</span>
        <span>{endLabel}</span>
      </div>
      {index !== null && (
        <div className="pointer-events-none absolute top-1 rounded border border-line-strong bg-raised px-2 py-1 font-mono text-[11px] shadow-lg" style={{ left: `${(index / (n - 1)) * 100}%`, transform: index > n / 2 ? "translateX(calc(-100% - 8px))" : "translateX(8px)" }}>
          {series.map((s) => (
            <div key={s.label} className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full" style={{ background: s.color }} />
              {s.label} {formatValue(s.values[index] ?? 0)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
