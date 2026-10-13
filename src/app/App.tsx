import { Sidebar } from "@/app/Sidebar";
import { StatusBar } from "@/app/StatusBar";
import { Titlebar } from "@/app/Titlebar";
import { Workspace } from "@/app/Workspace";
import { DropOverlay, Notices, OpenProgressCard } from "@/app/Overlays";
import { useFileDrop } from "@/hooks/useFileDrop";
import { useCaptureEvents } from "@/hooks/useCaptureEvents";

export function App() {
  useCaptureEvents();
  useFileDrop();
  return (
    <div className="flex h-full flex-col">
      <Titlebar />
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <Workspace />
      </div>
      <StatusBar />
      <OpenProgressCard />
      <DropOverlay />
      <Notices />
    </div>
  );
}
