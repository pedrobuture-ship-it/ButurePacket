import { EmptyState, ResizablePanel } from "@/components/ui";
import { usePacketsStore } from "@/stores/packets";
import { PacketTable } from "./PacketTable";

export function PacketsView() {
  const inspectorOpen = usePacketsStore((s) => s.inspectorOpen);
  const selectedId = usePacketsStore((s) => s.selectedId);
  return (
    <div className="flex h-full min-h-0">
      <div className="min-w-0 flex-1">
        <PacketTable />
      </div>
      {inspectorOpen && (
        <ResizablePanel id="packet-inspector" side="left" defaultSize={340} min={260} max={720} className="border-l border-line bg-surface">
          {selectedId === null ? <EmptyState title="No packet selected" description="Select a packet to inspect its layers." /> : null}
        </ResizablePanel>
      )}
    </div>
  );
}
