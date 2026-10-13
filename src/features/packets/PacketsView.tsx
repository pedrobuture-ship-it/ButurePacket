import { ResizablePanel } from "@/components/ui";
import { usePacketsStore } from "@/stores/packets";
import { PacketInspector } from "./PacketInspector";
import { PacketTable } from "./PacketTable";

export function PacketsView() {
  const inspectorOpen = usePacketsStore((s) => s.inspectorOpen);
  return (
    <div className="flex h-full min-h-0">
      <div className="min-w-0 flex-1">
        <PacketTable />
      </div>
      {inspectorOpen && (
        <ResizablePanel id="packet-inspector" side="left" defaultSize={500} min={300} max={760} className="border-l border-line bg-surface">
          <PacketInspector />
        </ResizablePanel>
      )}
    </div>
  );
}
