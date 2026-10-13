import { Activity, BarChart3, Database, Globe, LayoutDashboard, List, Network, PanelLeftClose, PanelLeftOpen, Radio, Settings, Workflow } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Tooltip } from "@/components/ui";
import { useUiStore, type ViewId } from "@/stores/ui";

interface Item {
  id: ViewId;
  label: string;
  icon: ReactNode;
}

const main: Item[] = [
  { id: "overview", label: "Overview", icon: <LayoutDashboard size={17} /> },
  { id: "capture", label: "Capture", icon: <Radio size={17} /> },
  { id: "packets", label: "Packets", icon: <List size={17} /> },
  { id: "flows", label: "Flows", icon: <Workflow size={17} /> },
  { id: "map", label: "Network Map", icon: <Network size={17} /> },
  { id: "timeline", label: "Timeline", icon: <Activity size={17} /> },
  { id: "dns", label: "DNS", icon: <Globe size={17} /> },
  { id: "analytics", label: "Analytics", icon: <BarChart3 size={17} /> },
];

const secondary: Item[] = [
  { id: "saved", label: "Saved Captures", icon: <Database size={17} /> },
  { id: "settings", label: "Settings", icon: <Settings size={17} /> },
];

function NavButton({ item, collapsed }: { item: Item; collapsed: boolean }) {
  const view = useUiStore((s) => s.view);
  const setView = useUiStore((s) => s.setView);
  const active = view === item.id;
  const button = (
    <button
      type="button"
      aria-current={active ? "page" : undefined}
      aria-label={item.label}
      onClick={() => setView(item.id)}
      className={cn(
        "flex h-9 w-full items-center gap-3 rounded border px-3 text-[13px] transition-colors duration-150",
        collapsed && "justify-center px-0",
        active ? "border-primary-muted bg-primary-muted/30 text-fg" : "border-transparent text-muted hover:bg-hover hover:text-fg",
      )}
    >
      <span className={active ? "text-primary" : undefined}>{item.icon}</span>
      {!collapsed && item.label}
    </button>
  );
  return collapsed ? (
    <Tooltip label={item.label} side="right">
      <span className="flex w-full">{button}</span>
    </Tooltip>
  ) : (
    button
  );
}

export function Sidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggle = useUiStore((s) => s.toggleSidebar);
  return (
    <nav
      aria-label="Main"
      className={cn("flex shrink-0 flex-col gap-1 border-r border-line bg-surface p-2 transition-[width] duration-150", collapsed ? "w-14" : "w-[200px]")}
    >
      {main.map((i) => (
        <NavButton key={i.id} item={i} collapsed={collapsed} />
      ))}
      <div className="my-2 h-px bg-line" />
      {secondary.map((i) => (
        <NavButton key={i.id} item={i} collapsed={collapsed} />
      ))}
      <div className="flex-1" />
      <button
        type="button"
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        onClick={toggle}
        className="flex h-8 items-center justify-center rounded text-muted transition-colors duration-150 hover:bg-hover hover:text-fg"
      >
        {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
      </button>
    </nav>
  );
}
