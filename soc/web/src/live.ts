import { useEffect, useRef, useState } from "react";
import { getToken, wsUrl } from "./api/client";
import type { Alert } from "./api/types";

/** Subscribe to /ws/alerts. The token goes in the first message (never the URL).
 *  Reconnects with back-off; stops if the server says the token is no longer valid. */
export function useLiveAlerts(onAlert: (a: Alert) => void): boolean {
  const [connected, setConnected] = useState(false);
  const handler = useRef(onAlert);
  handler.current = onAlert;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stopped = false;
    let retry = 1000;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      const token = getToken();
      if (!token || stopped) return;
      ws = new WebSocket(wsUrl("/ws/alerts"));
      ws.onopen = () => ws?.send(JSON.stringify({ token }));
      ws.onmessage = (ev) => {
        let msg: unknown;
        try {
          msg = JSON.parse(String(ev.data));
        } catch {
          return;
        }
        if (msg && typeof msg === "object" && "type" in msg && (msg as { type: string }).type === "ready") {
          setConnected(true);
          retry = 1000;
          return;
        }
        if (msg && typeof msg === "object" && "id" in msg) handler.current(msg as Alert);
      };
      ws.onclose = (ev) => {
        setConnected(false);
        if (stopped || ev.code === 4401) return; // not authorised: don't hammer the server
        timer = setTimeout(connect, retry);
        retry = Math.min(retry * 2, 30_000);
      };
    };

    connect();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return connected;
}
