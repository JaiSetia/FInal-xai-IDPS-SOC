import { useCallback, useEffect, useRef } from "react";
import type { Alert } from "./api/types";
import { useLiveAlerts } from "./live";

/** Call `reload` shortly after new alerts arrive (debounced), and every `everyMs` as a fallback.
 *  Returns whether the live feed is connected. */
export function useLiveRefresh(reload: () => void, onAlert?: (a: Alert) => void, everyMs = 30_000): boolean {
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  const alertRef = useRef(onAlert);
  alertRef.current = onAlert;

  const live = useLiveAlerts(useCallback((a: Alert) => {
    alertRef.current?.(a);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => reloadRef.current(), 1500);
  }, []));

  useEffect(() => {
    const id = setInterval(() => reloadRef.current(), everyMs);
    return () => {
      clearInterval(id);
      if (timer.current) clearTimeout(timer.current);
    };
  }, [everyMs]);

  return live;
}
