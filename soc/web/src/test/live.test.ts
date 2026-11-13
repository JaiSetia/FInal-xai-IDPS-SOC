import { StrictMode, createElement } from "react";
import { act, render, renderHook } from "@testing-library/react";
import { getToken, setToken } from "../api/client";
import { useLiveAlerts, useLiveStatus } from "../live";

class FakeWS {
  static all: FakeWS[] = [];
  url: string;
  sent: string[] = [];
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: ((e: { code: number }) => void) | null = null;
  constructor(url: string) { this.url = url; FakeWS.all.push(this); }
  send(d: string) { this.sent.push(d); }
  close() { this.closed = true; }
  open() { this.onopen?.(); }
  msg(o: unknown) { this.onmessage?.({ data: JSON.stringify(o) }); }
  drop(code = 1006) { this.onclose?.({ code }); }
}

beforeEach(() => {
  FakeWS.all = [];
  vi.stubGlobal("WebSocket", FakeWS);
  setToken("tok-123");
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  setToken(null);
});

describe("shared live socket", () => {
  it("opens one socket for two hooks, sends the token as first message, not in URL", () => {
    const a = renderHook(() => useLiveStatus());
    const b = renderHook(() => useLiveAlerts(() => {}));
    expect(FakeWS.all).toHaveLength(1);
    const s = FakeWS.all[0];
    expect(s.url).toContain("/ws/alerts");
    expect(s.url).not.toContain("tok-123");
    act(() => s.open());
    expect(JSON.parse(s.sent[0])).toEqual({ token: "tok-123" });
    a.unmount(); b.unmount();
  });

  it("ready flips both hooks to connected", () => {
    const a = renderHook(() => useLiveStatus());
    const b = renderHook(() => useLiveAlerts(() => {}));
    expect(a.result.current).toBe(false);
    act(() => { FakeWS.all[0].open(); FakeWS.all[0].msg({ type: "ready" }); });
    expect(a.result.current).toBe(true);
    expect(b.result.current).toBe(true);
    a.unmount(); b.unmount();
  });

  it("delivers alerts to every listener and ignores non-alert messages", () => {
    const f1 = vi.fn(), f2 = vi.fn();
    const a = renderHook(() => useLiveAlerts(f1));
    const b = renderHook(() => useLiveAlerts(f2));
    act(() => { FakeWS.all[0].msg({ id: 7, label: "x" }); FakeWS.all[0].msg({ type: "heartbeat" }); });
    expect(f1).toHaveBeenCalledTimes(1);
    expect(f2).toHaveBeenCalledWith({ id: 7, label: "x" });
    a.unmount(); b.unmount();
  });

  it("closes when the last subscriber unmounts, not before", () => {
    const a = renderHook(() => useLiveStatus());
    const b = renderHook(() => useLiveAlerts(() => {}));
    a.unmount();
    expect(FakeWS.all[0].closed).toBe(false);
    b.unmount();
    expect(FakeWS.all[0].closed).toBe(true);
  });

  it("does not reconnect after close code 4401", () => {
    vi.useFakeTimers();
    const a = renderHook(() => useLiveStatus());
    act(() => FakeWS.all[0].drop(4401));
    act(() => { vi.advanceTimersByTime(120_000); });
    expect(FakeWS.all).toHaveLength(1);
    expect(a.result.current).toBe(false);
    a.unmount();
  });

  it("reconnects with back-off after a normal close", () => {
    vi.useFakeTimers();
    const a = renderHook(() => useLiveStatus());
    act(() => { FakeWS.all[0].msg({ type: "ready" }); });
    expect(a.result.current).toBe(true);
    act(() => FakeWS.all[0].drop());
    expect(a.result.current).toBe(false);
    act(() => { vi.advanceTimersByTime(999); });
    expect(FakeWS.all).toHaveLength(1);
    act(() => { vi.advanceTimersByTime(1); });
    expect(FakeWS.all).toHaveLength(2);
    act(() => FakeWS.all[1].drop());
    act(() => { vi.advanceTimersByTime(1999); });
    expect(FakeWS.all).toHaveLength(2);
    act(() => { vi.advanceTimersByTime(1); });
    expect(FakeWS.all).toHaveLength(3);
    a.unmount();
  });

  it("opens no socket without a token", () => {
    setToken(null);
    const a = renderHook(() => useLiveStatus());
    expect(FakeWS.all).toHaveLength(0);
    a.unmount();
  });

  it("4401 clears the token and does not reconnect", () => {
    vi.useFakeTimers();
    const a = renderHook(() => useLiveStatus());
    act(() => FakeWS.all[0].drop(4401));
    expect(getToken()).toBeNull();
    act(() => { vi.advanceTimersByTime(120_000); });
    expect(FakeWS.all).toHaveLength(1);
    a.unmount();
  });

  it("token change closes the old socket and reconnects with the new token", () => {
    const a = renderHook(() => useLiveStatus());
    const first = FakeWS.all[0];
    act(() => { first.open(); first.msg({ type: "ready" }); });
    act(() => setToken("other"));
    expect(first.closed).toBe(true);
    expect(a.result.current).toBe(false);
    expect(FakeWS.all).toHaveLength(2);
    const second = FakeWS.all[1];
    expect(second.url).not.toContain("other");
    act(() => second.open());
    expect(JSON.parse(second.sent[0])).toEqual({ token: "other" });
    a.unmount();
  });

  it("clearing the token closes the socket and opens none", () => {
    const a = renderHook(() => useLiveStatus());
    act(() => setToken(null));
    expect(FakeWS.all[0].closed).toBe(true);
    expect(FakeWS.all).toHaveLength(1);
    a.unmount();
  });

  it("a throwing listener does not stop the others", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const good = vi.fn();
    const a = renderHook(() => useLiveAlerts(() => { throw new Error("boom"); }));
    const b = renderHook(() => useLiveAlerts(good));
    act(() => FakeWS.all[0].msg({ id: 1 }));
    expect(good).toHaveBeenCalledWith({ id: 1 });
    expect(err).toHaveBeenCalled();
    a.unmount(); b.unmount();
    err.mockRestore();
  });

  it("back-off keeps doubling when ready is followed by an immediate drop", () => {
    vi.useFakeTimers();
    const a = renderHook(() => useLiveStatus());
    for (const [i, delay] of [1000, 2000, 4000].entries()) {
      act(() => { FakeWS.all[i].msg({ type: "ready" }); FakeWS.all[i].drop(); });
      act(() => { vi.advanceTimersByTime(delay - 1); });
      expect(FakeWS.all).toHaveLength(i + 1);
      act(() => { vi.advanceTimersByTime(1); });
      expect(FakeWS.all).toHaveLength(i + 2);
    }
    a.unmount();
  });

  it("back-off resets to 1s after a connection stayed ready for 10s", () => {
    vi.useFakeTimers();
    const a = renderHook(() => useLiveStatus());
    act(() => FakeWS.all[0].drop());               // retry now 2s
    act(() => { vi.advanceTimersByTime(1000); });
    act(() => { FakeWS.all[1].msg({ type: "ready" }); });
    act(() => { vi.advanceTimersByTime(10_000); });
    act(() => FakeWS.all[1].drop());
    act(() => { vi.advanceTimersByTime(1000); });
    expect(FakeWS.all).toHaveLength(3);
    a.unmount();
  });

  it("StrictMode mount/unmount/mount leaves exactly one live socket", () => {
    const seen: boolean[] = [];
    function Probe() { seen.push(useLiveStatus()); return null; }
    const a = render(createElement(StrictMode, null, createElement(Probe)));
    const state = () => seen[seen.length - 1];
    const live = FakeWS.all.filter((s) => !s.closed);
    expect(live).toHaveLength(1);
    const first = FakeWS.all[0];
    act(() => live[0].msg({ type: "ready" }));
    expect(state()).toBe(true);
    act(() => first.drop());                        // late close of the first socket
    expect(state()).toBe(true);
    expect(FakeWS.all).toHaveLength(2);
    expect(first.closed).toBe(true);
    expect(FakeWS.all.filter((s) => !s.closed)).toHaveLength(1);
    a.unmount();
  });

  it("unmounting during back-off cancels the reconnect", () => {
    vi.useFakeTimers();
    const a = renderHook(() => useLiveStatus());
    act(() => FakeWS.all[0].drop());
    a.unmount();
    act(() => { vi.advanceTimersByTime(60_000); });
    expect(FakeWS.all).toHaveLength(1);
  });
});
