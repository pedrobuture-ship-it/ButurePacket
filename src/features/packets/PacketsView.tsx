import { ResizablePanel } from "@/components/ui";
import { usePacketsStore } from "@/stores/packets";
import { PacketInspector } from "./PacketInspector";
import { StoredSearchBar } from "./StoredSearchBar";
import { PacketTable } from "./PacketTable";

export function PacketsView() {
  const inspectorOpen = usePacketsStore((s) => s.inspectorOpen);
  return (
    <div className="flex h-full min-h-0">
      <div className="flex min-w-0 flex-1 flex-col">
        <StoredSearchBar />
        <div className="min-h-0 flex-1">
          <PacketTable />
        </div>
      </div>
      {inspectorOpen && (
        <ResizablePanel id="packet-inspector" side="left" defaultSize={500} min={300} max={760} className="border-l border-line bg-surface">
          <PacketInspector />
        </ResizablePanel>
      )}
    </div>
  );
}
