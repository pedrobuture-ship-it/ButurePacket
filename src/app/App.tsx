import { Sidebar } from "@/app/Sidebar";
import { StatusBar } from "@/app/StatusBar";
import { Titlebar } from "@/app/Titlebar";
import { Workspace } from "@/app/Workspace";
import { useCaptureEvents } from "@/hooks/useCaptureEvents";

export function App() {
  useCaptureEvents();
  return (
    <div className="flex h-full flex-col">
      <Titlebar />
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <Workspace />
      </div>
      <StatusBar />
    </div>
  );
}
