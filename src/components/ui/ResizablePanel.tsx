import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { clamp, loadSize, saveSize } from "@/lib/layout";

interface Props {
  /** Persistence key; the size is stored locally. */
  id: string;
  side: "left" | "right" | "top" | "bottom";
  defaultSize: number;
  min?: number;
  max?: number;
  children: ReactNode;
  className?: string;
}

/** A fixed-size region whose `side` edge (the one touching the content) is draggable. */
export function ResizablePanel({ id, side, defaultSize, min = 160, max = 900, children, className }: Props) {
  const [size, setSize] = useState(() => clamp(loadSize(id, defaultSize), min, max));
  const sizeRef = useRef(size);
  useEffect(() => {
    sizeRef.current = size;
  }, [size]);
  const horizontal = side === "left" || side === "right";

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      e.preventDefault();
      const start = horizontal ? e.clientX : e.clientY;
      const startSize = sizeRef.current;
      // `left` means the handle is on the left edge, so dragging left grows the panel.
      const dir = side === "left" || side === "top" ? -1 : 1;
      const move = (ev: PointerEvent) => {
        const delta = ((horizontal ? ev.clientX : ev.clientY) - start) * dir;
        setSize(clamp(startSize + delta, min, max));
      };
      const up = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
        saveSize(id, sizeRef.current);
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
    },
    [horizontal, side, min, max, id],
  );

  const handlePos = { left: "left-0 top-0 h-full w-1 cursor-col-resize", right: "right-0 top-0 h-full w-1 cursor-col-resize", top: "top-0 left-0 h-1 w-full cursor-row-resize", bottom: "bottom-0 left-0 h-1 w-full cursor-row-resize" }[side];

  return (
    <div className={cn("relative shrink-0", className)} style={horizontal ? { width: size } : { height: size }}>
      {children}
      <div
        role="separator"
        aria-orientation={horizontal ? "vertical" : "horizontal"}
        aria-label="Resize panel"
        tabIndex={0}
        onPointerDown={onPointerDown}
        onKeyDown={(e) => {
          const step = e.shiftKey ? 40 : 10;
          const grow = side === "left" || side === "top" ? ["ArrowLeft", "ArrowUp"] : ["ArrowRight", "ArrowDown"];
          const shrink = side === "left" || side === "top" ? ["ArrowRight", "ArrowDown"] : ["ArrowLeft", "ArrowUp"];
          const d = grow.includes(e.key) ? step : shrink.includes(e.key) ? -step : 0;
          if (d) {
            const next = clamp(sizeRef.current + d, min, max);
            setSize(next);
            saveSize(id, next);
          }
        }}
        className={cn("absolute z-10 bg-transparent transition-colors duration-150 hover:bg-primary-muted/60 focus-visible:bg-primary-muted/60", handlePos)}
      />
    </div>
  );
}
