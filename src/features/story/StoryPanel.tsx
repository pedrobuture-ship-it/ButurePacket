import { useMemo } from "react";
import { Eye, Lightbulb } from "lucide-react";
import { Badge } from "@/components/ui";
import { dnsBuffer, useDnsStore } from "@/stores/dns";
import { eventBuffer, useEventsStore } from "@/stores/events";
import type { FlowView } from "@/types/ipc";
import { buildStory } from "./story";

export function useStory(flow: FlowView) {
  const dnsVersion = useDnsStore((s) => s.version);
  const eventVersion = useEventsStore((s) => s.version);
  return useMemo(() => {
    const events = eventBuffer.rows.filter((e) => e.flowId === flow.id);
    return buildStory(flow, events, dnsBuffer.byId.values());
  }, [flow, dnsVersion, eventVersion]); // eslint-disable-line react-hooks/exhaustive-deps
}

/** Observed facts and clearly-labelled inferences, side by side in meaning, never mixed. */
export function StoryPanel({ flow }: { flow: FlowView }) {
  const story = useStory(flow);
  return (
    <div className="selectable flex flex-col gap-5 text-[13px]">
      <section aria-label="Observed">
        <h3 className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted">
          <Eye size={13} /> Observed <Badge tone="success">from packets</Badge>
        </h3>
        <ol className="flex list-decimal flex-col gap-1.5 pl-5 marker:font-mono marker:text-faint">
          {story.observed.map((s, i) => (
            <li key={i}>{s.text}</li>
          ))}
        </ol>
      </section>
      {story.inferred.length > 0 && (
        <section aria-label="Inferred" className="rounded border border-dashed border-warning/50 bg-warning/5 p-3">
          <h3 className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-warning">
            <Lightbulb size={13} /> Inferred <Badge tone="warning">not directly observed</Badge>
          </h3>
          <ul className="flex flex-col gap-2">
            {story.inferred.map((s, i) => (
              <li key={i}>
                <p>{s.text}</p>
                <p className="text-xs text-muted">Based on: {s.basis}</p>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
