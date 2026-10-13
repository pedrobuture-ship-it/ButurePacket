import { cn } from "@/lib/cn";

export function Divider({ vertical, className }: { vertical?: boolean; className?: string }) {
  return (
    <div
      role="separator"
      aria-orientation={vertical ? "vertical" : "horizontal"}
      className={cn("shrink-0 bg-line", vertical ? "mx-1 h-full w-px" : "my-1 h-px w-full", className)}
    />
  );
}
