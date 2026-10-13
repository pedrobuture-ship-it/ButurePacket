import { useMemo, useState } from "react";
import { Select, ResizablePanel, EmptyState } from "@/components/ui";
import { FlowSubject } from "@/lib/filter/adapters";
import { filterItems } from "@/lib/filter/apply";
import { flowBuffer, useFlowsStore } from "@/stores/flows";
import { useUiStore } from "@/stores/ui";
import { FlowInspector } from "./FlowInspector";
import { FlowTable } from "./FlowTable";
import { FLOW_SORTS, type FlowSort, sortFlows } from "./sort";

export function FlowsView() {
  const version = useFlowsStore((s) => s.version);
  const selectedId = useFlowsStore((s) => s.selectedId);
  const select = useFlowsStore((s) => s.select);
  const [sort, setSort] = useState<FlowSort>("traffic");
  const filterAst = useUiStore((s) => s.filterAst);

  const flows = useMemo(() => sortFlows(filterItems(flowBuffer.byId.values(), filterAst, new FlowSubject()), sort), [version, sort, filterAst]); // eslint-disable-line react-hooks/exhaustive-deps
  const selected = selectedId === null ? null : (flowBuffer.byId.get(selectedId) ?? null);

  return (
    <div className="flex h-full min-h-0">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex h-10 shrink-0 items-center gap-3 border-b border-line px-3 text-xs text-muted">
          <span className="font-mono">{flows.length.toLocaleString("en-US")} flows</span>
          <div className="flex-1" />
          <label className="flex items-center gap-2">
            Sort by
            <Select aria-label="Sort flows" value={sort} options={FLOW_SORTS} onChange={(e) => setSort(e.target.value as FlowSort)} />
          </label>
        </div>
        <div className="min-h-0 flex-1">
          <FlowTable flows={flows} selectedId={selectedId} onSelect={select} />
        </div>
      </div>
      <ResizablePanel id="flow-inspector" side="left" defaultSize={440} min={340} max={720} className="border-l border-line bg-surface">
        {selected ? <FlowInspector flow={selected} /> : <EmptyState title="No flow selected" description="Select a flow to see its direction, traffic and TCP behaviour." />}
      </ResizablePanel>
    </div>
  );
}
