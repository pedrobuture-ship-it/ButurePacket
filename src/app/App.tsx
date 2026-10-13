import { Sidebar } from "@/app/Sidebar";
import { StatusBar } from "@/app/StatusBar";
import { Titlebar } from "@/app/Titlebar";
import { Workspace } from "@/app/Workspace";
import { CommandPalette } from "@/app/CommandPalette";
import { ShortcutsModal } from "@/app/ShortcutsModal";
import { useGlobalErrorHandlers } from "@/hooks/useGlobalErrorHandlers";
import { useGlobalShortcuts } from "@/hooks/useGlobalShortcuts";
import { DropOverlay, Notices, OpenProgressCard } from "@/app/Overlays";
import { useFileDrop } from "@/hooks/useFileDrop";
import { usePermissionCheck } from "@/hooks/usePermissionCheck";
import { useCaptureEvents } from "@/hooks/useCaptureEvents";

export function App() {
  useCaptureEvents();
  useFileDrop();
  usePermissionCheck();
  useGlobalShortcuts();
  useGlobalErrorHandlers();
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
      <CommandPalette />
      <ShortcutsModal />
    </div>
  );
}
