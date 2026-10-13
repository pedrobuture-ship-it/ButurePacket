import { FilterBar } from "@/app/FilterBar";
import { EmptyState } from "@/components/ui";
import { DnsView } from "@/features/dns/DnsView";
import { FlowsView } from "@/features/flows/FlowsView";
import { TimelineView } from "@/features/timeline/TimelineView";
import { TopologyView } from "@/features/topology/TopologyView";
import { PacketsView } from "@/features/packets/PacketsView";
import { useUiStore, type ViewId } from "@/stores/ui";

const titles: Record<ViewId, string> = {
  overview: "Overview",
  capture: "Capture",
  packets: "Packets",
  flows: "Flows",
  map: "Network Map",
  timeline: "Timeline",
  dns: "DNS",
  analytics: "Analytics",
  saved: "Saved Captures",
  settings: "Settings",
};

/** Views that depend on the global filter show the filter bar. */
const filterable: ViewId[] = ["packets", "flows"];

export function Workspace() {
  const view = useUiStore((s) => s.view);
  return (
    <main className="flex min-w-0 flex-1 flex-col bg-bg">
      {filterable.includes(view) && <FilterBar />}
      <div className="min-h-0 flex-1" key={view}>
        {view === "packets" ? (
          <PacketsView />
        ) : view === "flows" ? (
          <FlowsView />
        ) : view === "dns" ? (
          <DnsView />
        ) : view === "map" ? (
          <TopologyView />
        ) : view === "timeline" ? (
          <TimelineView />
        ) : (
          <EmptyState title={titles[view]} description="Nothing captured yet. Start a capture or open a PCAP file." />
        )}
      </div>
    </main>
  );
}
