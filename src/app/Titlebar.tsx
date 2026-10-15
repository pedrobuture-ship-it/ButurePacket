import { Minus, Square, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { IconButton } from "@/components/ui";
import { CaptureToolbar } from "@/app/CaptureToolbar";
import { LiveMetrics } from "@/app/LiveMetrics";

const win = () => {
  try {
    return getCurrentWindow();
  } catch {
    return null;
  }
};

function Logo() {
  return (
    <div className="flex w-[220px] shrink-0 items-center gap-2.5 pl-4" data-tauri-drag-region>
      <svg width="26" height="26" viewBox="0 0 1024 1024" aria-hidden className="pointer-events-none">
        <rect x="40" y="40" width="944" height="944" rx="170" fill="none" stroke="#24503E" strokeWidth="56" />
        <path d="M130 540 H330 L400 300 L530 760 L630 420 L700 540 H894" fill="none" stroke="#58E38C" strokeWidth="72" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div className="pointer-events-none leading-tight">
        <div className="text-[15px] font-semibold text-primary">B&M Packet</div>
        <div className="whitespace-nowrap text-[10px] text-muted">A modern network traffic explorer</div>
      </div>
    </div>
  );
}

export function Titlebar() {
  return (
    <header className="flex h-14 shrink-0 items-center border-b border-line bg-surface" data-tauri-drag-region>
      <Logo />
      <CaptureToolbar />
      <div className="flex-1" data-tauri-drag-region />
      <LiveMetrics />
      <div className="flex items-center self-start">
        <IconButton label="Minimize" className="rounded-none" onClick={() => win()?.minimize()}>
          <Minus size={14} />
        </IconButton>
        <IconButton label="Maximize" className="rounded-none" onClick={() => win()?.toggleMaximize()}>
          <Square size={12} />
        </IconButton>
        <IconButton label="Close" className="rounded-none hover:!bg-danger/30" onClick={() => win()?.close()}>
          <X size={14} />
        </IconButton>
      </div>
    </header>
  );
}
