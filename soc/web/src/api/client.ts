// Small fetch wrapper for the SOC API.
//
// The access token lives in memory, with a copy in sessionStorage so a page refresh keeps
// you logged in; it is gone when the tab closes. It is never put in a URL or a cookie.
// The dashboard never renders API data as HTML (no dangerouslySetInnerHTML), which is what
// keeps a token in storage safe from injected markup in alert fields.

const BASE = "/api";
const STORAGE_KEY = "idps-soc-token";

let token: string | null = null;
try {
  token = sessionStorage.getItem(STORAGE_KEY);
} catch {
  token = null;
}

type Listener = () => void;
const listeners = new Set<Listener>();

export function getToken(): string | null {
  return token;
}

export function setToken(value: string | null): void {
  token = value;
  try {
    if (value) sessionStorage.setItem(STORAGE_KEY, value);
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable: keep the in-memory copy only */
  }
  listeners.forEach((fn) => fn());
}

export function onTokenChange(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function detailMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) {
      return d
        .map((e) => (e && typeof e === "object" && "msg" in e ? String(e.msg) : String(e)))
        .join("; ");
    }
  }
  return fallback;
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  const res = await fetch(BASE + path, { ...init, headers, body });
  if (res.status === 401 && token) setToken(null); // expired or revoked: back to login
  const text = await res.text();
  const data = text ? safeJson(text) : null;
  if (!res.ok) throw new ApiError(res.status, detailMessage(data, `${res.status} ${res.statusText}`));
  return data as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

export function wsUrl(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${BASE}${path}`;
}
