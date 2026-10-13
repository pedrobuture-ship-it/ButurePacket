import type { BadgeTone } from "@/components/ui";

/** Badge tone per protocol label, tuned to stay discreet on the dark palette. */
const tones: Record<string, BadgeTone> = {
  DNS: "info",
  MDNS: "info",
  TCP: "success",
  HTTP: "success",
  TLS: "primary",
  QUIC: "warning",
  UDP: "neutral",
  ICMP: "warning",
  ICMPv6: "warning",
  ARP: "neutral",
  SSH: "primary",
  DHCP: "neutral",
  NTP: "neutral",
};

export function protocolTone(protocol: string): BadgeTone {
  return tones[protocol] ?? "neutral";
}
