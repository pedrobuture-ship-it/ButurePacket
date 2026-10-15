import { copyText } from "@/lib/clipboard";
import { useEffect } from "react";
import { CheckCircle2, Copy, RefreshCw, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { Badge, Button, EmptyState, Panel, type BadgeTone } from "@/components/ui";
import { cn } from "@/lib/cn";
import { sanitizeText } from "@/lib/sanitize";
import { usePermissionStore } from "@/stores/permission";
import type { PermissionState } from "@/types/ipc";

const STATE: Record<PermissionState, { label: string; tone: BadgeTone; icon: typeof ShieldCheck; color: string }> = {
  available: { label: "Available", tone: "success", icon: ShieldCheck, color: "text-primary" },
  limited: { label: "Limited", tone: "warning", icon: ShieldQuestion, color: "text-warning" },
  unavailable: { label: "Unavailable", tone: "danger", icon: ShieldAlert, color: "text-danger" },
};

function Fact({ label, value }: { label: string; value: boolean | null }) {
  return (
    <div className="flex items-center justify-between gap-6 text-xs">
      <span className="text-muted">{label}</span>
      <span className={cn("font-mono", value === null ? "text-muted" : value ? "text-primary" : "text-danger")}>{value === null ? "unknown" : value ? "yes" : "no"}</span>
    </div>
  );
}

/** "Packet Capture Permission": what the OS allows, and how to fix it — never automatically. */
export function CaptureView() {
  const { report, checking, error, check } = usePermissionStore();
  useEffect(() => {
    if (!report) void check();
  }, [report, check]);

  if (!report) {
    return (
      <div className="p-6">
        <Panel title="Packet Capture Permission">
          <EmptyState title={error ? "Could not check permission" : "Checking permission…"} description={error ?? "Looking at what this application is allowed to do."} action={error ? <Button onClick={() => void check()}>Try again</Button> : undefined} />
        </Panel>
      </div>
    );
  }

  const s = STATE[report.state];
  const Icon = s.icon;
  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto flex max-w-3xl flex-col gap-4">
        <Panel title="Packet Capture Permission" actions={<Button size="sm" variant="ghost" icon={<RefreshCw size={12} className={checking ? "animate-spin" : undefined} />} onClick={() => void check()} disabled={checking}>Check again</Button>} bodyClassName="flex flex-col gap-4 p-5">
          <div className="flex items-center gap-4">
            <Icon size={34} className={s.color} />
            <div>
              <p className="flex items-center gap-2 text-base font-medium">
                {s.label} <Badge tone={s.tone}>{report.state}</Badge>
              </p>
              <p className="text-sm text-muted">{report.summary}</p>
            </div>
          </div>

          <div className="selectable flex flex-col gap-2 text-[13px]">
            {report.guidance.map((line) => (
              <p key={line} className={report.state === "available" ? "text-muted" : undefined}>
                {line}
              </p>
            ))}
          </div>

          {report.commands.length > 0 && (
            <div className="rounded border border-line bg-bg">
              <div className="flex items-center justify-between border-b border-line px-3 py-1.5 text-[11px] text-muted">
                <span>Run this yourself in a terminal — B&M Packet will not run it</span>
              </div>
              {report.commands.map((c) => (
                <div key={c} className="flex items-center gap-3 px-3 py-2">
                  <code className="selectable flex-1 break-all font-mono text-xs text-fg">{sanitizeText(c)}</code>
                  <Button size="sm" icon={<Copy size={12} />} onClick={() => copyText(c)}>
                    Copy
                  </Button>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Details" bodyClassName="grid gap-6 p-5 sm:grid-cols-2">
          <div className="flex flex-col gap-2">
            <Fact label="Running as root" value={report.runningAsRoot} />
            <Fact label="CAP_NET_RAW" value={report.hasNetRaw} />
            <Fact label="CAP_NET_ADMIN" value={report.hasNetAdmin} />
            <div className="flex items-center justify-between gap-6 text-xs">
              <span className="text-muted">Platform</span>
              <span className="font-mono">{report.platform}</span>
            </div>
          </div>
          {report.executable && (
            <div className="min-w-0 text-xs">
              <p className="text-muted">Program</p>
              <p className="selectable break-all font-mono">{sanitizeText(report.executable)}</p>
            </div>
          )}
        </Panel>

        <Panel title={`Interfaces (${report.interfaces.length})`} bodyClassName="divide-y divide-line/60">
          {report.interfaces.length === 0 && <p className="p-4 text-xs text-muted">No interfaces were found.</p>}
          {report.interfaces.map((i) => (
            <div key={i.name} className="flex items-center gap-3 px-4 py-2 text-xs">
              {i.openable ? <CheckCircle2 size={14} className="text-primary" /> : <ShieldAlert size={14} className="text-muted" />}
              <span className="w-40 shrink-0 truncate font-mono text-fg">{sanitizeText(i.name)}</span>
              <span className="min-w-0 flex-1 truncate text-muted">{sanitizeText(i.description ?? "")}</span>
              <span className={cn("shrink-0", i.openable ? "text-primary" : "text-muted")}>{i.openable ? "can capture" : "not permitted"}</span>
            </div>
          ))}
        </Panel>
      </div>
    </div>
  );
}
