import { useEffect, useState } from "react";
import { Keyboard, RotateCcw, ShieldCheck } from "lucide-react";
import { Button, Panel } from "@/components/ui";
import { api } from "@/lib/api";
import { notifyError } from "@/lib/notify";
import { loadPersistSetting, resetLayout, savePersistSetting } from "@/lib/settings";
import { useAppStore } from "@/stores/app";
import { useUiStore } from "@/stores/ui";

function Row({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-6 px-4 py-3">
      <div className="min-w-0">
        <p className="text-[13px] text-fg">{title}</p>
        <p className="text-xs text-muted">{description}</p>
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

export function SettingsView() {
  const info = useAppStore((s) => s.info);
  const setInfo = useAppStore((s) => s.setInfo);
  const setView = useUiStore((s) => s.setView);
  const setShortcutsOpen = useUiStore((s) => s.setShortcutsOpen);
  const [persist, setPersist] = useState(loadPersistSetting);

  useEffect(() => {
    if (!info) api.appInfo().then(setInfo).catch(() => undefined);
  }, [info, setInfo]);

  const togglePersist = () => {
    const next = !persist;
    setPersist(next);
    savePersistSetting(next);
    api.setPersistence(next).catch(notifyError);
  };

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto flex max-w-3xl flex-col gap-4">
        <Panel title="Captures" bodyClassName="divide-y divide-line/60">
          <Row title="Store captures on disk while analysing" description="Keeps packet summaries, flows, DNS and events in a local database so very large captures can be searched. Applies to the next capture or file. Payload bytes are never stored.">
            <button type="button" role="switch" aria-checked={persist} onClick={togglePersist} className={`relative h-5 w-9 rounded-full border transition-colors duration-150 ${persist ? "border-primary-muted bg-primary-muted/50" : "border-line-strong bg-raised"}`}>
              <span className={`absolute top-0.5 h-3.5 w-3.5 rounded-full bg-fg transition-all duration-150 ${persist ? "left-[1.2rem]" : "left-0.5"}`} />
              <span className="sr-only">Store captures on disk</span>
            </button>
          </Row>
          <Row title="Packet capture permission" description="Check whether this app may capture packets, and how to enable it.">
            <Button size="sm" icon={<ShieldCheck size={13} />} onClick={() => setView("capture")}>
              Open Capture screen
            </Button>
          </Row>
        </Panel>

        <Panel title="Interface" bodyClassName="divide-y divide-line/60">
          <Row title="Keyboard shortcuts" description="Every shortcut, including the command palette (Ctrl+K).">
            <Button size="sm" icon={<Keyboard size={13} />} onClick={() => setShortcutsOpen(true)}>
              Show shortcuts
            </Button>
          </Row>
          <Row title="Reset layout" description="Forgets saved panel sizes and the collapsed sidebar, then reloads the window.">
            <Button
              size="sm"
              icon={<RotateCcw size={13} />}
              onClick={() => {
                resetLayout();
                window.location.reload();
              }}
            >
              Reset and reload
            </Button>
          </Row>
        </Panel>

        <Panel title="About" bodyClassName="flex flex-col gap-2 p-4 text-xs">
          <p className="text-[13px] text-fg">
            ButurePacket <span className="font-mono text-muted">{info ? `v${info.version}` : ""}</span> <span className="text-faint">{info?.platform}</span>
          </p>
          <p className="text-muted">A modern network traffic explorer. Everything runs on this computer: no account, no cloud, no telemetry, no packet injection. Captured data stays here unless you save or share it yourself.</p>
        </Panel>
      </div>
    </div>
  );
}
