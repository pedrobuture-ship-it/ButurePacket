import { FolderOpen, Pause, Play, Save, Settings, Square, Trash2 } from "lucide-react";
import { Button, IconButton, Select } from "@/components/ui";
import { useCaptureStore } from "@/stores/capture";
import { useUiStore } from "@/stores/ui";
import { captureActions } from "@/lib/captureActions";

export function CaptureToolbar() {
  const { state, interfaces, selectedInterface, selectInterface } = useCaptureStore();
  const setView = useUiStore((s) => s.setView);
  const stats = useCaptureStore((s) => s.stats);
  const running = state === "capturing";
  const paused = state === "paused";
  const busy = state === "processing";
  const options = interfaces.length
    ? interfaces.map((i) => ({ value: i.name, label: i.description ? `${i.name} — ${i.description}` : i.name }))
    : [{ value: "", label: "No interfaces" }];

  return (
    <div className="flex items-center gap-2 px-2" role="toolbar" aria-label="Capture controls">
      <Select
        aria-label="Capture interface"
        className="w-44"
        value={selectedInterface ?? ""}
        disabled={running || paused || busy}
        options={options}
        onChange={(e) => selectInterface(e.target.value)}
      />
      {paused ? (
        <Button variant="primary" icon={<Play size={14} />} onClick={captureActions.resume}>
          Resume
        </Button>
      ) : (
        <Button variant="primary" icon={<Play size={14} />} disabled={running || busy || !selectedInterface} onClick={captureActions.start}>
          Start
        </Button>
      )}
      <Button icon={<Pause size={14} />} disabled={!running} onClick={captureActions.pause}>
        Pause
      </Button>
      <Button variant="danger" icon={<Square size={12} />} disabled={!running && !paused} onClick={captureActions.stop}>
        Stop
      </Button>
      <IconButton label="Clear capture" disabled={running || busy} onClick={captureActions.clear}>
        <Trash2 size={15} />
      </IconButton>
      <Button icon={<FolderOpen size={14} />} disabled={running || busy} onClick={captureActions.openFile}>
        Open PCAP
      </Button>
      <Button icon={<Save size={14} />} disabled={busy || stats.packets === 0} onClick={captureActions.save}>
        Save Capture
      </Button>
      <IconButton label="Settings" onClick={() => setView("settings")}>
        <Settings size={15} />
      </IconButton>
    </div>
  );
}
