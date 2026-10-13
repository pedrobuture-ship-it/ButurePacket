import { useEffect } from "react";
import { api } from "@/lib/api";
import { useAppStore } from "@/stores/app";

export function App() {
  const info = useAppStore((s) => s.info);
  const setInfo = useAppStore((s) => s.setInfo);

  useEffect(() => {
    api.appInfo().then(setInfo).catch(() => undefined);
  }, [setInfo]);

  return (
    <main className="flex h-full items-center justify-center font-mono text-sm">
      ButurePacket {info ? `v${info.version}` : ""}
    </main>
  );
}
