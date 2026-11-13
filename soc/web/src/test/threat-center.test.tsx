import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import ThreatCenter, { ago, searchTarget, TC_WINDOWS } from "../pages/ThreatCenter";

const h = vi.hoisted(() => ({ api: vi.fn(), onAlert: null as null | ((a: unknown) => void), reload: null as null | (() => void) }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (f: () => void, onAlert?: (a: unknown) => void) => { if (onAlert) { h.onAlert = onAlert; h.reload = f; } return true; },
}));
vi.mock("../pages/WorldMap", () => ({
  default: (p: { hours: number; compact?: boolean }) => <div>map-stub hours={p.hours} compact={String(!!p.compact)}</div>,
}));

const iso = (ms: number) => new Date(Date.now() + ms).toISOString();
const alert = (o: Record<string, unknown> = {}) => ({
  id: 1, sensor_id: 1, predicted_class: "PortScan", confidence: 0.9, severity: "high", status: "new",
  src_ip: "10.0.0.1", src_port: 1000, dst_ip: "10.0.0.9", dst_port: 22, protocol: "TCP",
  received_at: iso(-5 * 60_000), ...o,
});
const block = (o: Record<string, unknown> = {}) => ({
  id: 1, ip: "10.0.0.1", sensor_id: 1, source: "auto", reason: "scan", alert_id: null, active: true,
  blocked_at: iso(-60_000), expires_at: iso(600_000), unblocked_at: null, ...o,
});
const action = (o: Record<string, unknown> = {}) => ({
  id: 3, kind: "block_ip", status: "pending", proposed_by: "assistant", sensor_id: 1, reason: "looks bad",
  params: { ip: "10.0.0.5", ttl_seconds: 900 }, result: null, created_at: iso(-1000), ...o,
});
const metrics = (o: Record<string, unknown> = {}) => ({
  alerts_total: 1234, by_class: { PortScan: 50, DoS: 10 }, top_sources: [{ ip: "10.0.0.1", count: 7 }],
  alerts_per_bucket: [{ count: 1 }, { count: 4 }], detection_latency: { p50_ms: 1500, p95_ms: 4000 },
  active_blocks: 2, false_positive_rate: 0.2, false_positives: 2, triaged: 10, ...o,
});

let d: {
  metrics: unknown; blocks: unknown[]; alerts: unknown[]; actions: unknown[]; next: string | null; topo: unknown;
};
const page = (items: unknown[], next_cursor: string | null = null) => ({ items, total: items.length, next_cursor });
const calls = (prefix: string) => h.api.mock.calls.map(([p]) => String(p)).filter((p) => p.startsWith(prefix));

beforeEach(() => {
  d = { metrics: metrics(), blocks: [], alerts: [], actions: [], next: null, topo: { hours: 24, nodes: [], edges: [] } };
  h.api.mockReset();
  h.onAlert = null;
  h.api.mockImplementation(async (path: string) => {
    if (path.startsWith("/metrics/summary")) return d.metrics;
    if (path.startsWith("/blocks")) return page(d.blocks);
    if (path.startsWith("/alerts")) return page(d.alerts);
    if (path.startsWith("/actions")) return page(d.actions, d.next);
    if (path.startsWith("/topology")) return d.topo;
    throw new Error(`unexpected ${path}`);
  });
});

function Loc() { const l = useLocation(); return <div data-testid="loc">{l.pathname + l.search}</div>; }
const show = (url = "/") => render(<MemoryRouter initialEntries={[url]}><ThreatCenter /><Loc /></MemoryRouter>);
const loc = () => screen.getByTestId("loc").textContent;
const liveCard = () => screen.getByText("Live alerts").closest(".card") as HTMLElement;
const cardOf = (title: string) => screen.getByText(title).closest(".card") as HTMLElement;
const bodyRows = () => within(liveCard()).getAllByRole("row").slice(1);

describe("ago", () => {
  const now = Date.parse("2026-01-01T12:00:00Z");
  it.each([
    ["2026-01-01T11:59:30Z", "just now"],
    ["2026-01-01T12:00:30Z", "just now"], // future clamps to 0
    ["2026-01-01T11:56:00Z", "4 min ago"],
    ["2026-01-01T09:00:00Z", "3 h ago"],
    ["2025-12-30T12:00:00Z", "2 d ago"],
    ["2026-01-01T11:59:00Z", "1 min ago"],
    ["nonsense", "—"],
  ])("%s -> %s", (iso_, text) => { expect(ago(iso_, now)).toBe(text); });
});

describe("searchTarget", () => {
  it.each([
    ["42", "/alerts/42"], ["#42", "/alerts/42"], ["  #7 ", "/alerts/7"],
    ["10.0.0.1", "/alerts?ip=10.0.0.1"], ["::1", "/alerts?ip=%3A%3A1"], ["fe80::1", "/alerts?ip=fe80%3A%3A1"],
    ["PortScan", "/alerts?class=PortScan"], ["DoS Hulk", "/alerts?class=DoS+Hulk"],
  ])("%s -> %s", (raw, to) => {
    const got = searchTarget(raw)!;
    expect(decodeURIComponent(got.replace(/\+/g, " "))).toBe(decodeURIComponent(to.replace(/\+/g, " ")));
  });
  it.each([[""], ["   "]])("blank -> null", (raw) => { expect(searchTarget(raw)).toBeNull(); });
});

it("TC_WINDOWS is 1, 24, 168", () => { expect(TC_WINDOWS).toEqual([1, 24, 168]); });

describe("requests and window", () => {
  it("fetches every endpoint with defaults and passes compact to the map", async () => {
    show();
    await screen.findByText("1,234");
    expect(calls("/metrics/summary")).toEqual(["/metrics/summary?hours=24"]);
    expect(calls("/blocks")).toEqual(["/blocks?active=true&limit=200"]);
    expect(calls("/alerts")).toEqual(["/alerts?limit=10"]);
    expect(calls("/actions")).toEqual(["/actions?status=pending&limit=20"]);
    expect(calls("/topology")).toEqual(["/topology?hours=24"]);
    expect(await screen.findByText("map-stub hours=24 compact=true")).toBeInTheDocument();
  });

  it("?hours=168 is honoured; an invalid value falls back to 24", async () => {
    show("/?hours=168");
    await screen.findByText("1,234");
    expect(calls("/metrics/summary")).toEqual(["/metrics/summary?hours=168"]);
    expect(screen.getByLabelText("Window")).toHaveValue("168");
  });

  it("invalid hours -> 24", async () => {
    show("/?hours=5");
    await screen.findByText("1,234");
    expect(screen.getByLabelText("Window")).toHaveValue("24");
  });

  it("changing the window sets ?hours=, default 24 is omitted, and data refetches", async () => {
    show();
    await screen.findByText("1,234");
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "1" } });
    await waitFor(() => expect(loc()).toBe("/?hours=1"));
    await waitFor(() => expect(calls("/metrics/summary")).toContain("/metrics/summary?hours=1"));
    expect(calls("/topology")).toContain("/topology?hours=1");
    fireEvent.change(screen.getByLabelText("Window"), { target: { value: "24" } });
    await waitFor(() => expect(loc()).toBe("/"));
  });
});

describe("search", () => {
  const submit = (text: string) => {
    fireEvent.change(screen.getByLabelText("Search alerts"), { target: { value: text } });
    fireEvent.submit(screen.getByRole("search"));
  };
  it.each([
    ["#12", "/alerts/12"], ["12", "/alerts/12"], ["1.2.3.4", "/alerts?ip=1.2.3.4"], ["PortScan", "/alerts?class=PortScan"],
  ])("%s navigates to %s", async (text, to) => {
    show();
    await screen.findByText("1,234");
    submit(text);
    expect(loc()).toBe(to);
  });
  it("blank does not navigate", async () => {
    show();
    await screen.findByText("1,234");
    submit("  ");
    expect(loc()).toBe("/");
  });
});

describe("KPIs", () => {
  it("shows values, latency, false positives and class line", async () => {
    show();
    expect(await screen.findByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("p95 4.0 s")).toBeInTheDocument();
    expect(screen.getByText("2 of 10 triaged")).toBeInTheDocument();
    expect(screen.getByText("PortScan 50 · DoS 10")).toBeInTheDocument();
    expect(within(cardOf("Active blocks")).getByText("2")).toBeInTheDocument();
  });
  it("shows placeholders while loading and a dash without latency", async () => {
    d.metrics = metrics({ detection_latency: null });
    show();
    expect(within(cardOf("Alerts")).getByText("…")).toBeInTheDocument();
    await screen.findByText("1,234");
    expect(within(cardOf("Detection latency (p50)")).getByText("—")).toBeInTheDocument();
  });
  it("shows a metrics error", async () => {
    h.api.mockImplementation(async (p: string) => {
      if (p.startsWith("/metrics")) throw new Error("metrics down");
      if (p.startsWith("/topology")) return d.topo;
      return page([]);
    });
    show();
    expect(await screen.findByText("metrics down")).toBeInTheDocument();
  });
});

describe("attack classes and sources", () => {
  it("links classes and top sources", async () => {
    show();
    const classes = within(await screen.findByText("Attack classes").then((e) => e.closest(".card") as HTMLElement));
    expect(classes.getByRole("link", { name: "PortScan" })).toHaveAttribute("href", "/alerts?class=PortScan");
    expect(classes.getByRole("link", { name: "10.0.0.1" })).toHaveAttribute("href", "/alerts?ip=10.0.0.1");
    expect(classes.getByText("7 alerts")).toBeInTheDocument();
  });
  it("empty states", async () => {
    d.metrics = metrics({ by_class: {}, top_sources: [] });
    show();
    expect(await screen.findByText("No alerts in this window.")).toBeInTheDocument();
    expect(screen.getByText("None in this window.")).toBeInTheDocument();
  });
});

describe("live alerts table", () => {
  beforeEach(() => {
    d.alerts = [
      alert({ id: 1, severity: "low", confidence: 0.99, src_ip: "10.0.0.1" }),
      alert({ id: 2, severity: "critical", confidence: 0.5, src_ip: "10.0.0.2" }),
      alert({ id: 3, severity: "high", confidence: 0.7, src_ip: "10.0.0.3" }),
    ];
  });
  const ids = () => bodyRows().map((r) => /#(\d+)/.exec(r.textContent ?? "")![1]);

  it("sorts newest first by default, then by severity and confidence", async () => {
    show();
    await within(liveCard()).findByText("#3 · 5 min ago");
    expect(ids()).toEqual(["3", "2", "1"]);
    fireEvent.change(within(liveCard()).getByLabelText("Sort"), { target: { value: "severity" } });
    expect(ids()).toEqual(["2", "3", "1"]);
    fireEvent.change(within(liveCard()).getByLabelText("Sort"), { target: { value: "confidence" } });
    expect(ids()).toEqual(["1", "3", "2"]);
    expect(calls("/alerts").length).toBe(1);
  });

  it("severity filter refetches with severity", async () => {
    show();
    await within(liveCard()).findByText("#3 · 5 min ago");
    fireEvent.change(within(liveCard()).getByLabelText("Severity"), { target: { value: "high" } });
    await waitFor(() => expect(calls("/alerts")).toContain("/alerts?severity=high&limit=10"));
  });

  it("empty states", async () => {
    d.alerts = [];
    show();
    expect(await screen.findByText("No alerts yet.")).toBeInTheDocument();
    fireEvent.change(within(liveCard()).getByLabelText("Severity"), { target: { value: "high" } });
    expect(await screen.findByText("No alerts yet with severity high.")).toBeInTheDocument();
  });

  it("clicking a row opens the alert; the class link too", async () => {
    show();
    const links = await within(liveCard()).findAllByRole("link", { name: "PortScan" });
    expect(links[0]).toHaveAttribute("href", "/alerts/3");
    fireEvent.click(bodyRows()[1]);
    expect(loc()).toBe("/alerts/2");
  });

  it("Response column: blocked with source, else observe", async () => {
    d.blocks = [
      block({ id: 1, ip: "10.0.0.1", source: "auto" }),
      block({ id: 2, ip: "10.0.0.2", source: "analyst" }),
      block({ id: 3, ip: "10.0.0.2", source: "auto" }), // newest-first: first one wins
      block({ id: 4, ip: "10.0.0.3", source: "auto", active: false }),
    ];
    show();
    await within(liveCard()).findByText("blocked · auto");
    const rows = Object.fromEntries(bodyRows().map((r) => [/#(\d+)/.exec(r.textContent!)![1], r.textContent]));
    expect(rows["1"]).toContain("blocked · auto");
    expect(rows["2"]).toContain("blocked · analyst");
    expect(rows["3"]).toContain("observe");
  });

  describe("live feed", () => {
    it("prepends new alerts, dedupes, and caps at 10", async () => {
      d.alerts = Array.from({ length: 10 }, (_, i) => alert({ id: i + 1 }));
      show();
      await within(liveCard()).findByText("#10 · 5 min ago");
      act(() => h.onAlert!(alert({ id: 11, predicted_class: "Fresh" })));
      expect(bodyRows().length).toBe(10);
      expect(ids()[0]).toBe("11");
      expect(ids()).not.toContain("10"); // the last row falls off the end
      const before = bodyRows().length;
      act(() => h.onAlert!(alert({ id: 11 })));
      expect(bodyRows().length).toBe(before);
      expect(bodyRows()[0]).toHaveClass("fresh");
    });

    it("ignores alerts that do not match the severity filter", async () => {
      show();
      await within(liveCard()).findByText("#3 · 5 min ago");
      fireEvent.change(within(liveCard()).getByLabelText("Severity"), { target: { value: "high" } });
      await waitFor(() => expect(calls("/alerts").length).toBe(2));
      act(() => h.onAlert!(alert({ id: 20, severity: "low" })));
      expect(ids()).not.toContain("20");
      act(() => h.onAlert!(alert({ id: 21, severity: "high" })));
      expect(ids()).toContain("21");
    });

    it("shows Live status", async () => {
      show();
      expect(await screen.findByText("Live")).toBeInTheDocument();
    });
  });
});

describe("firewall card", () => {
  it("hides expired blocks, shows 3 and an All N link", async () => {
    d.blocks = [
      block({ id: 1, ip: "1.1.1.1" }), block({ id: 2, ip: "2.2.2.2" }), block({ id: 3, ip: "3.3.3.3" }),
      block({ id: 4, ip: "4.4.4.4" }),
      block({ id: 5, ip: "5.5.5.5", blocked_at: iso(-120_000), expires_at: iso(-60_000) }),
    ];
    show();
    const card = within(await screen.findByText("Firewall · nftables").then((e) => e.closest(".card") as HTMLElement));
    await waitFor(() => expect(card.getByText("4 active")).toBeInTheDocument());
    expect(card.getByRole("link", { name: "1.1.1.1" })).toHaveAttribute("href", "/alerts?ip=1.1.1.1");
    expect(card.queryByText("4.4.4.4")).toBeNull();
    expect(card.queryByText("5.5.5.5")).toBeNull();
    expect(card.getByRole("link", { name: "All 4 blocks →" })).toHaveAttribute("href", "/response");
  });

  it("3 or fewer: plain link; none: empty text", async () => {
    show();
    expect(await screen.findByText("No address is blocked right now.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All blocks →" })).toHaveAttribute("href", "/response");
    expect(screen.getByText("0 active")).toBeInTheDocument();
  });

  it("shows the reason or a fallback", async () => {
    d.blocks = [block({ reason: "scan" }), block({ id: 2, ip: "9.9.9.9", reason: "" })];
    show();
    expect(await screen.findByText("auto · scan")).toBeInTheDocument();
    expect(screen.getByText("auto · no reason given")).toBeInTheDocument();
  });
});

describe("decisions card", () => {
  it("empty", async () => {
    show();
    expect(await screen.findByText("Nothing waits for a decision.")).toBeInTheDocument();
    expect(screen.getByText("0 pending")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Decide in Response →" })).toBeNull();
  });

  it("count, up to 3 items, summary text and link", async () => {
    d.actions = [1, 2, 3, 4].map((i) => action({ id: i, proposed_by: i === 2 ? "user" : "assistant" }));
    show();
    const card = within(await screen.findByText("Needs your decision").then((e) => e.closest(".card") as HTMLElement));
    expect(await card.findByText("4 pending")).toBeInTheDocument();
    expect(card.getAllByText("block ip 10.0.0.5 · 15 min · sensor #1")).toHaveLength(3);
    expect(card.getByText("Proposed by an analyst")).toBeInTheDocument();
    expect(card.getAllByText("Proposed by the assistant")).toHaveLength(2);
    expect(card.getAllByText("“looks bad”")).toHaveLength(3);
    expect(card.getByRole("link", { name: "Decide in Response →" })).toHaveAttribute("href", "/response");
  });

  it("next_cursor makes the count N+", async () => {
    d.actions = [action()];
    d.next = "more";
    show();
    expect(await screen.findByText("1+ pending")).toBeInTheDocument();
  });
});

describe("sensor health and topology", () => {
  it("sensor health waits for data", async () => {
    show();
    expect(await screen.findByText("waiting for data")).toBeInTheDocument();
  });

  it("topology summary: counts, top 4 edges by count, link opens Maps", async () => {
    d.topo = {
      hours: 168,
      nodes: [{ ip: "a" }, { ip: "b" }, { ip: "c" }],
      edges: ["1", "2", "3", "4", "5"].map((n, i) => ({ src: `s${n}`, dst: "t", count: i + 1, max_severity: "high" })),
    };
    show("/?hours=168");
    expect(await screen.findByText("3 hosts · 5 links, last 7 days")).toBeInTheDocument();
    const card = within(cardOf("Topology"));
    expect(card.getAllByRole("listitem")).toHaveLength(4);
    expect(card.getByText("s5 → t")).toBeInTheDocument();
    expect(card.queryByText("s1 → t")).toBeNull();
    expect(card.getByRole("link", { name: "Open →" })).toHaveAttribute("href", "/maps");
  });

  it("topology link omits hours for 1 h; empty edges text", async () => {
    show("/?hours=1");
    expect(await screen.findByText("No traffic with alerts in this window.")).toBeInTheDocument();
    expect(within(cardOf("Topology")).getByRole("link", { name: "Open →" })).toHaveAttribute("href", "/maps");
  });
});

describe("searchTarget with known classes", () => {
  const known = ["PortScan", "DoS Hulk", "DDoS", "(other)"];
  it("matches a known class ignoring case", () => {
    expect(searchTarget("portscan", known)).toBe("/alerts?class=PortScan");
  });
  it("a unique partial picks the class", () => {
    expect(searchTarget("hulk", known)).toBe("/alerts?class=DoS+Hulk");
  });
  it("an ambiguous partial is sent as typed", () => {
    expect(searchTarget("dos", known)).toBe("/alerts?class=dos");
  });
  it("(other) is never chosen, by exact or partial match", () => {
    expect(searchTarget("(other)", known)).toBe("/alerts?class=%28other%29");
    expect(searchTarget("other", known)).toBe("/alerts?class=other");
  });
  it("unknown text and no known list are sent as typed; numbers and IPs win", () => {
    expect(searchTarget("zzz", known)).toBe("/alerts?class=zzz");
    expect(searchTarget("portscan")).toBe("/alerts?class=portscan");
    expect(searchTarget("7", known)).toBe("/alerts/7");
    expect(searchTarget("1.2.3.4", known)).toBe("/alerts?ip=1.2.3.4");
  });
  it("the page passes the by_class keys", async () => {
    d.metrics = metrics({ by_class: { "DoS Hulk": 5, PortScan: 3 } });
    show();
    await screen.findByText("1,234");
    fireEvent.change(screen.getByLabelText("Search alerts"), { target: { value: "hulk" } });
    fireEvent.submit(screen.getByRole("search"));
    expect(loc()).toBe("/alerts?class=DoS+Hulk");
  });
});

describe("review fixes", () => {
  afterEach(() => vi.useRealTimers());

  it("(other) is plain text, not a link", async () => {
    d.metrics = metrics({ by_class: { PortScan: 5, "(other)": 2 } });
    show();
    const card = within(await screen.findByText("Attack classes").then((e) => e.closest(".card") as HTMLElement));
    expect(card.getByText("other classes")).toBeInTheDocument();
    expect(card.queryByRole("link", { name: /other/ })).toBeNull();
    expect(card.getByRole("link", { name: "PortScan" })).toBeInTheDocument();
  });

  it("Response column ignores blocks that have expired", async () => {
    d.alerts = [alert({ id: 1, src_ip: "10.0.0.1" }), alert({ id: 2, src_ip: "10.0.0.2" })];
    d.blocks = [
      block({ ip: "10.0.0.1", blocked_at: iso(-120_000), expires_at: iso(-60_000) }),
      block({ id: 2, ip: "10.0.0.2" }),
    ];
    show();
    await within(liveCard()).findByText("blocked · auto");
    const txt = bodyRows().map((r) => r.textContent!);
    expect(txt.find((t) => t.includes("#1 "))).toContain("observe");
    expect(txt.find((t) => t.includes("#2 "))).toContain("blocked · auto");
  });

  it("a paged /blocks shows N+ active and All N+ blocks", async () => {
    h.api.mockImplementation(async (path: string) => {
      if (path.startsWith("/blocks")) return page([1, 2, 3, 4].map((i) => block({ id: i, ip: `1.1.1.${i}` })), "more");
      if (path.startsWith("/metrics/summary")) return d.metrics;
      if (path.startsWith("/alerts")) return page([]);
      if (path.startsWith("/actions")) return page([]);
      return d.topo;
    });
    show();
    expect(await screen.findByText("4+ active")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All 4+ blocks →" })).toHaveAttribute("href", "/response");
  });

  it("without next_cursor there is no plus", async () => {
    d.blocks = [block()];
    show();
    expect(await screen.findByText("1 active")).toBeInTheDocument();
  });

  it("the empty row stays visible while a reload is in flight", async () => {
    show();
    expect(await screen.findByText("No alerts yet.")).toBeInTheDocument();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    h.api.mockImplementation(async (path: string) => {
      if (path.startsWith("/alerts")) { await gate; return page([]); }
      return path.startsWith("/metrics") ? d.metrics : path.startsWith("/topology") ? d.topo : page([]);
    });
    act(() => { h.reload!(); });
    expect(screen.getByText("No alerts yet.")).toBeInTheDocument();
    release();
    await waitFor(() => expect(screen.getByText("No alerts yet.")).toBeInTheDocument());
  });

  it("a live row loses fresh after 2 s; timers are cleared on unmount", async () => {
    d.alerts = [alert({ id: 1 })];
    const { unmount } = show();
    await within(liveCard()).findByText("#1 · 5 min ago");
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    act(() => h.onAlert!(alert({ id: 2 })));
    expect(bodyRows()[0]).toHaveClass("fresh");
    act(() => { vi.advanceTimersByTime(1900); });
    expect(bodyRows()[0]).toHaveClass("fresh");
    act(() => { vi.advanceTimersByTime(200); });
    expect(bodyRows()[0]).not.toHaveClass("fresh");
    act(() => h.onAlert!(alert({ id: 3 })));
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("decisions poll /actions every 15 s and a live alert does not refetch them", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "setTimeout", "clearTimeout"] });
    show();
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    expect(calls("/actions").length).toBe(1);
    act(() => h.onAlert!(alert({ id: 50 })));
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(calls("/actions").length).toBe(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(calls("/actions").length).toBe(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
    expect(calls("/actions").length).toBe(3);
  });

  it("the decisions interval stops on unmount", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "setTimeout", "clearTimeout"] });
    const { unmount } = show();
    await act(async () => { await vi.advanceTimersByTimeAsync(10); });
    unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(calls("/actions").length).toBe(1);
  });

  it("topology edge badge has sr-only text and a title", async () => {
    d.topo = { hours: 24, nodes: [{ ip: "a" }], edges: [{ src: "a", dst: "b", count: 3, max_severity: "high" }] };
    show();
    const sr = await screen.findByText("alerts, highest severity high", { exact: false });
    expect(sr).toHaveClass("sr-only");
    expect(sr.closest(".badge")).toHaveAttribute("title", "highest severity: high");
    expect(sr.closest(".badge")).toHaveTextContent("3 alerts, highest severity high");
  });

  it("the lazy map sits in one .stack cell", async () => {
    show();
    const map = await screen.findByText(/map-stub/);
    expect(map.parentElement).toHaveClass("stack");
    expect(map.parentElement!.children.length).toBe(1);
  });
});
