const PROTOCOLS: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6" };

export function protocolName(n: number): string {
  return PROTOCOLS[n] ?? String(n);
}

export function endpoint(ip: string, port: number, protocol: number): string {
  if (protocol !== 6 && protocol !== 17) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

export function dateTime(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
}

export function percent(x: number | null | undefined, digits = 0): string {
  return x === null || x === undefined ? "—" : `${(x * 100).toFixed(digits)}%`;
}

export function num(x: number | null | undefined, digits = 3): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return Math.abs(x) >= 1000 ? x.toLocaleString(undefined, { maximumFractionDigits: 0 }) : x.toFixed(digits);
}

export function label(s: string): string {
  return s.replace(/_/g, " ");
}
