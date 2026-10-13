import { useEffect } from "react";
import { Database, Loader2 } from "lucide-react";
import { Button } from "@/components/ui";
import { toStoredQuery } from "@/lib/filter/stored";
import { formatCount } from "@/lib/format";
import { PAGE_SIZE, useStoredSearch } from "@/stores/storedSearch";
import { useStorageStore } from "@/stores/storage";
import { useUiStore } from "@/stores/ui";

/**
 * Lets the packet list show matches from the whole stored capture (millions of rows on disk) instead
 * of only what fits in memory. Only filters that map onto indexed columns can be searched there.
 */
export function StoredSearchBar() {
  const storage = useStorageStore((s) => s.status);
  const filterAst = useUiStore((s) => s.filterAst);
  const { enabled, loading, rows, total, error, unsupported, setEnabled, setUnsupported, load, loadMore } = useStoredSearch();
  const query = toStoredQuery(filterAst);

  // Re-run the search when it is switched on, when the filter changes, or when more rows were stored.
  const written = Math.floor(storage.packetsWritten / 1000);
  useEffect(() => {
    if (!enabled) return;
    const q = toStoredQuery(filterAst);
    if (!q.ok) {
      setUnsupported(q.reason);
      return;
    }
    const timer = setTimeout(() => void load(q.query), 150);
    return () => clearTimeout(timer);
  }, [enabled, filterAst, written, load, setUnsupported]);

  if (!storage.active && !enabled) return null;
  return (
    <div className="flex shrink-0 items-center gap-3 border-b border-line bg-surface px-3 py-1 text-xs">
      <Button size="sm" variant={enabled ? "primary" : "ghost"} icon={<Database size={12} />} aria-pressed={enabled} onClick={() => setEnabled(!enabled)}>
        {enabled ? "Stored capture" : "Search stored capture"}
      </Button>
      {!enabled && <span className="text-muted">{formatCount(storage.packetsWritten)} packets stored on disk</span>}
      {enabled && loading && <Loader2 size={13} className="animate-spin text-muted" aria-label="Searching" />}
      {enabled && unsupported && <span className="text-warning">This filter can’t be searched in the stored capture: {unsupported}.</span>}
      {enabled && error && (
        <span role="alert" className="text-danger">
          {error.message} {error.hint}
        </span>
      )}
      {enabled && !unsupported && !error && !loading && (
        <span className="font-mono text-muted">
          {formatCount(rows.length)} of {formatCount(total)} {query.ok && Object.keys(query.query).length > 0 ? "matches" : "stored packets"}
        </span>
      )}
      {enabled && rows.length < total && !unsupported && (
        <Button size="sm" variant="ghost" disabled={loading} onClick={() => query.ok && void loadMore(query.query)}>
          Load {formatCount(Math.min(PAGE_SIZE, total - rows.length))} more
        </Button>
      )}
    </div>
  );
}
