import { act, render } from "@testing-library/react";
import { useLiveRefresh } from "../useLiveRefresh";

const h = vi.hoisted(() => ({ listener: null as null | ((a: unknown) => void) }));
vi.mock("../live", () => ({
  useLiveAlerts: (fn: (a: unknown) => void) => { h.listener = fn; return true; },
}));

function Probe({ reload, onAlert, every }: { reload: () => void; onAlert?: (a: unknown) => void; every?: number }) {
  useLiveRefresh(reload, onAlert, every);
  return null;
}
const alert = () => act(() => { h.listener!({ id: 1 }); });
const tick = (ms: number) => act(() => { vi.advanceTimersByTime(ms); });

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => vi.useRealTimers());

describe("useLiveRefresh", () => {
  it("a single alert reloads after 1.5 s, not before", () => {
    const reload = vi.fn();
    render(<Probe reload={reload} />);
    alert();
    tick(1499);
    expect(reload).not.toHaveBeenCalled();
    tick(1);
    expect(reload).toHaveBeenCalledTimes(1);
    tick(3000);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("calls onAlert for every alert", () => {
    const onAlert = vi.fn();
    render(<Probe reload={vi.fn()} onAlert={onAlert} />);
    alert(); alert();
    expect(onAlert).toHaveBeenCalledTimes(2);
  });

  it("a quiet gap of 1.5 s is still a normal debounce", () => {
    const reload = vi.fn();
    render(<Probe reload={reload} />);
    alert(); tick(1000); alert(); tick(1000); alert();
    expect(reload).not.toHaveBeenCalled();
    tick(1500);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("a steady stream still reloads within 5 s of the first alert", () => {
    const reload = vi.fn();
    render(<Probe reload={reload} />);
    alert(); // t=0
    for (let i = 0; i < 4; i++) { tick(1000); alert(); } // t=4000
    expect(reload).not.toHaveBeenCalled();
    tick(999);
    expect(reload).not.toHaveBeenCalled();
    tick(1); // t=5000
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("an alert arriving after the max wait has passed reloads immediately", () => {
    const reload = vi.fn();
    render(<Probe reload={reload} />);
    alert(); // t=0
    tick(1400); alert(); tick(1400); alert(); tick(1400); alert(); // t=4200
    tick(790); // t=4990
    alert();   // wait = min(1500, 10) = 10
    expect(reload).not.toHaveBeenCalled();
    tick(10);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("firstAt resets after each reload", () => {
    const reload = vi.fn();
    render(<Probe reload={reload} />);
    alert(); tick(1500);
    expect(reload).toHaveBeenCalledTimes(1);
    tick(10_000); // later alert starts a fresh 5 s window and a normal 1.5 s wait
    alert();
    tick(1499);
    expect(reload).toHaveBeenCalledTimes(1);
    tick(1);
    expect(reload).toHaveBeenCalledTimes(2);
  });

  it("falls back to the interval and clears timers on unmount", () => {
    const reload = vi.fn();
    const { unmount } = render(<Probe reload={reload} every={1000} />);
    tick(3000);
    expect(reload).toHaveBeenCalledTimes(3);
    alert();
    unmount();
    expect(vi.getTimerCount()).toBe(0);
    tick(10_000);
    expect(reload).toHaveBeenCalledTimes(3);
  });
});
