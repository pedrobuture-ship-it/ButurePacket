import { useMemo, useRef, useState } from "react";
import { AlertCircle, Clock, Filter, Search } from "lucide-react";
import { Button, IconButton, Input } from "@/components/ui";
import { cn } from "@/lib/cn";
import { applySuggestion, suggest, type Suggestion } from "@/lib/filter/suggest";
import { RecentsCache, buildRecents } from "@/lib/filter/recents";
import { dnsBuffer, useDnsStore } from "@/stores/dns";
import { flowBuffer, useFlowsStore } from "@/stores/flows";
import { packetBuffer } from "@/stores/packets";
import { useUiStore } from "@/stores/ui";

const recentsCache = new RecentsCache();

/** Recent addresses and domains seen in captured traffic, for autocomplete. Cached per data version. */
function collectRecents() {
  const key = `${useFlowsStore.getState().version}|${useDnsStore.getState().version}|${packetBuffer.rows.length >> 9}`;
  return recentsCache.get(key, computeRecents);
}

function computeRecents() {
  const flows = [...flowBuffer.byId.values()].sort((a, b) => a.lastSeenAt - b.lastSeenAt);
  const tail = packetBuffer.rows.slice(-300);
  return buildRecents({
    ipsOldestFirst: [...flows.flatMap((f) => [f.endpointB.ip, f.endpointA.ip]), ...tail.flatMap((p) => [p.destinationIp, p.sourceIp])],
    domainsOldestFirst: [...flows.flatMap((f) => [...f.domains, f.tls?.sni]), ...[...dnsBuffer.byId.values()].slice(-200).map((t) => t.queryName)],
  });
}

export function FilterBar() {
  const { filterDraft, filter, filterError, setFilterDraft, applyFilter, clearFilter } = useUiStore();
  const inputRef = useRef<HTMLInputElement>(null);
  const [cursor, setCursor] = useState(0);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);

  const suggestions = useMemo(() => (open ? suggest(filterDraft, cursor, collectRecents()) : null), [open, filterDraft, cursor]);
  const items = suggestions?.items ?? [];

  const accept = (item: Suggestion) => {
    if (!suggestions) return;
    const next = applySuggestion(filterDraft, suggestions, item);
    setFilterDraft(next.text);
    setActive(0);
    requestAnimationFrame(() => {
      inputRef.current?.focus();
      inputRef.current?.setSelectionRange(next.cursor, next.cursor);
      setCursor(next.cursor);
    });
  };

  return (
    <div className="relative shrink-0 border-b border-line">
      <form
        className="flex items-center gap-2 p-2"
        onSubmit={(e) => {
          e.preventDefault();
          setOpen(false);
          applyFilter();
        }}
      >
        <Input
          id="global-filter"
          inputRef={inputRef}
          mono
          className="flex-1"
          invalid={filterError !== null}
          icon={<Search size={14} />}
          placeholder='Filter… (e.g. dns && latency > 50ms, ip = 192.168.1.20, domain contains "github")'
          aria-label="Filter"
          aria-invalid={filterError !== null}
          aria-autocomplete="list"
          aria-expanded={open && items.length > 0}
          value={filterDraft}
          onChange={(e) => {
            setFilterDraft(e.target.value);
            setCursor(e.target.selectionStart ?? e.target.value.length);
            setOpen(true);
            setActive(0);
          }}
          onSelect={(e) => setCursor(e.currentTarget.selectionStart ?? 0)}
          onBlur={() => setOpen(false)}
          onKeyDown={(e) => {
            if (open && items.length > 0) {
              if (e.key === "ArrowDown" || e.key === "ArrowUp") {
                e.preventDefault();
                setActive((a) => (a + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length);
                return;
              }
              if (e.key === "Tab" || (e.key === "Enter" && e.shiftKey)) {
                e.preventDefault();
                accept(items[active] ?? items[0]);
                return;
              }
            }
            if (e.key === "Escape") {
              if (open) setOpen(false);
              else clearFilter();
            }
          }}
        />
        <Button type="submit" variant="secondary">
          Apply
        </Button>
        <IconButton label="Clear filter" active={filter !== ""} onClick={clearFilter}>
          <Filter size={15} />
        </IconButton>
        <IconButton label="Filter history" disabled>
          <Clock size={15} />
        </IconButton>
      </form>
      {filterError && (
        <p role="alert" className="flex items-center gap-1.5 px-3 pb-2 font-mono text-xs text-danger">
          <AlertCircle size={13} /> {filterError}
        </p>
      )}
      {open && items.length > 0 && (
        <ul role="listbox" className="absolute left-2 top-11 z-40 w-[min(560px,90%)] overflow-hidden rounded border border-line-strong bg-raised py-1 shadow-xl animate-pop-in">
          {items.map((item, i) => (
            <li
              key={`${item.kind}-${item.label}`}
              role="option"
              aria-selected={i === active}
              onMouseDown={(e) => {
                e.preventDefault();
                accept(item);
              }}
              className={cn("flex cursor-pointer items-center gap-3 px-3 py-1 font-mono text-xs", i === active ? "bg-hover text-fg" : "text-muted")}
            >
              <span className="w-14 shrink-0 text-[10px] uppercase tracking-wide text-faint">{item.kind}</span>
              <span className="text-fg">{item.label}</span>
              {item.hint && <span className="truncate font-sans text-faint">{item.hint}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
