// Stand-in for the Tauri bridge so the web UI can run in a plain browser (headless Chromium over
// CDP). It answers only what the UI asks for at startup and for the inspector; everything else
// returns undefined. Test/demo use only — the real app talks to the Rust backend.
window.__TAURI_INTERNALS__ = {
  transformCallback: (cb) => {
    const id = Math.floor(Math.random() * 1e9);
    window["_" + id] = cb;
    return id;
  },
  unregisterCallback: () => {},
  invoke: async (cmd) => {
    (window.__calls = window.__calls || []).push(cmd);
    switch (cmd) {
      case "plugin:event|listen":
        return 1;
      case "plugin:event|unlisten":
        return undefined;
      case "list_capture_interfaces":
        return [
          { name: "eth0", description: "Intel I225-V 2.5GbE", addresses: ["192.168.1.20"], loopback: false, up: true },
          { name: "lo", description: null, addresses: ["127.0.0.1"], loopback: true, up: true },
        ];
      case "check_capture_permission":
        return {
          state: "available",
          platform: "linux",
          runningAsRoot: false,
          hasNetRaw: true,
          hasNetAdmin: true,
          interfaces: [
            { name: "eth0", description: "Intel I225-V 2.5GbE", openable: true, error: null },
            { name: "lo", description: null, openable: true, error: null },
          ],
          executable: "/usr/local/bin/buturepacket",
          summary: "Packet capture is available.",
          guidance: ["Live capture is available. You can start capturing from the toolbar."],
          commands: [],
        };
      case "list_recent_captures":
        return [];
      case "get_flow":
        return null;
      case "get_packet_detail":
        return window.__packetDetail ?? null;
      default:
        return undefined;
    }
  },
};
