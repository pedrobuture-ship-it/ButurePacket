import { useCallback, useEffect, useState } from "react";
import { FileClock, FolderOpen, Trash2 } from "lucide-react";
import { Button, EmptyState, IconButton, Panel } from "@/components/ui";
import { api } from "@/lib/api";
import { formatAgo, formatBytes } from "@/lib/format";
import { notifyError } from "@/lib/notify";
import { sanitizeText } from "@/lib/sanitize";
import { useCaptureStore } from "@/stores/capture";
import { useUiStore } from "@/stores/ui";
import type { RecentCapture } from "@/types/ipc";

/** Recently opened or saved capture files. The backend remembers the paths; this screen only sees ids. */
export function SavedView() {
  const [items, setItems] = useState<RecentCapture[] | null>(null);
  const busy = useCaptureStore((s) => ["capturing", "paused", "processing"].includes(s.state));
  const setView = useUiStore((s) => s.setView);

  const load = useCallback(() => {
    api
      .listRecentCaptures()
      .then((r) => setItems(r ?? []))
      .catch((e) => {
        setItems([]);
        notifyError(e);
      });
  }, []);
  useEffect(load, [load]);

  const open = async (id: number) => {
    try {
      await api.openRecentCapture(id);
      setView("overview");
    } catch (e) {
      notifyError(e);
    }
  };
  const forget = async (id: number | null) => {
    await api.forgetRecentCapture(id).catch(notifyError);
    load();
  };

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-3xl">
        <Panel
          title="Saved Captures"
          actions={
            <Button size="sm" variant="ghost" icon={<Trash2 size={12} />} disabled={!items?.length} onClick={() => void forget(null)}>
              Clear list
            </Button>
          }
        >
          {items === null ? (
            <EmptyState title="Loading…" />
          ) : items.length === 0 ? (
            <EmptyState icon={<FileClock size={28} />} title="No saved captures yet" description="Capture files you open or save show up here so you can get back to them quickly." />
          ) : (
            <ul className="divide-y divide-line/60">
              {items.map((c) => (
                <li key={c.id} className="flex items-center gap-3 px-4 py-2.5">
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px] text-fg">{sanitizeText(c.name)}</p>
                    <p className="truncate text-[11px] text-muted" title={sanitizeText(c.folder)}>
                      {sanitizeText(c.folder)}
                    </p>
                  </div>
                  <span className="w-24 shrink-0 text-right text-xs text-muted">{formatAgo(c.usedAt)}</span>
                  <span className="w-20 shrink-0 text-right font-mono text-xs text-muted">{c.exists && c.size !== null ? formatBytes(c.size) : "missing"}</span>
                  <Button size="sm" icon={<FolderOpen size={12} />} disabled={!c.exists || busy} onClick={() => void open(c.id)}>
                    Open
                  </Button>
                  <IconButton label="Remove from list" onClick={() => void forget(c.id)}>
                    <Trash2 size={13} />
                  </IconButton>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
