import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import AlertDetail, { activeBlock, relatedBlocks, timeline } from "../pages/AlertDetail";
import ExplanationChart from "../components/ExplanationChart";
import { ALERT_STATUSES } from "../api/types";
import { label } from "../format";

const h = vi.hoisted(() => ({ api: vi.fn(), live: null as null | { fn: () => void; ms: number | undefined } }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (fn: () => void, _a: unknown, ms?: number) => { h.live = { fn, ms }; return true; },
}));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));

const T = 1_700_000_000_000;
const iso = (ms: number) => new Date(ms).toISOString();
const H24 = 24 * 3600_000;

const mkAlert = (o: Record<string, unknown> = {}) => ({
  id: 7, sensor_id: 3, received_at: iso(T + 60_000), src_ip: "10.0.0.1", src_port: 1234, dst_ip: "10.0.0.2", dst_port: 80,
  protocol: 6, start_ms: T, end_ms: T + 1000, predicted_class: "PortScan", confidence: 0.95, anomaly_score: 0.5,
  severity: "high", status: "new", case_id: null,
  explanation: { method: "shap", predicted_class: "PortScan", top_features: [{ feature: "syn_count", value: 4, contribution: 1.2 }] },
  ...o,
}) as never;
const mkBlock = (o: Record<string, unknown> = {}) => ({
  id: 1, sensor_id: 3, ip: "10.0.0.1", reason: "scan", source: "auto", alert_id: null, blocked_at: iso(T + 5000),
  expires_at: iso(T + 3600_000), unblocked_at: null, active: true, ...o,
}) as never;

describe("relatedBlocks", () => {
  const a = mkAlert();
  const ids = (bs: unknown[]) => (relatedBlocks(a, bs as never) as { id: number }[]).map((b) => b.id);

  it("filters by sensor and ip", () => {
    expect(ids([mkBlock({ id: 1 }), mkBlock({ id: 2, sensor_id: 9 }), mkBlock({ id: 3, ip: "10.0.0.9" })])).toEqual([1]);
  });
  it("includes an alert_id match outside the window, but only for the same sensor and ip", () => {
    expect(ids([mkBlock({ id: 1, alert_id: 7, blocked_at: iso(T - 10 * H24) })])).toEqual([1]);
    expect(ids([mkBlock({ id: 2, alert_id: 7, sensor_id: 9, blocked_at: iso(T - 10 * H24) })])).toEqual([]);
  });
  it("is overlap based: in force during the flow, or started up to 1 h after receipt", () => {
    const recv = T + 60_000;
    expect(ids([
      mkBlock({ id: 1, blocked_at: iso(T - 5 * H24), expires_at: iso(T + 1) }),       // started before, still in force
      mkBlock({ id: 2, blocked_at: iso(T - 5 * H24), expires_at: iso(T - 1) }),       // ended before the flow
      mkBlock({ id: 3, blocked_at: iso(T - 5 * H24), expires_at: null }),             // no end
      mkBlock({ id: 4, blocked_at: iso(recv + 3600_000), expires_at: iso(recv + 9e6) }), // exactly 1 h after
      mkBlock({ id: 5, blocked_at: iso(recv + 2 * 3600_000), expires_at: iso(recv + 9e6) }), // 2 h after
      mkBlock({ id: 6, blocked_at: iso(T - 5 * H24), expires_at: iso(T - 9e6), unblocked_at: iso(T + 10) }), // unblocked during
      mkBlock({ id: 7, blocked_at: iso(T - 5 * H24), expires_at: iso(T + 9e6), unblocked_at: iso(T - 10) }), // unblocked before
    ])).toEqual([1, 3, 4, 6]);
  });
  it("caps at 10", () => {
    const many = Array.from({ length: 12 }, (_, i) => mkBlock({ id: i + 1 }));
    expect(ids(many).length).toBe(10);
  });
});

describe("activeBlock", () => {
  const a = mkAlert();
  const now = T + 10_000;
  const pick = (bs: unknown[]) => (activeBlock(a, bs as never, now) as { id: number } | undefined)?.id;
  it("finds a same sensor and ip block that is active and not over, whenever it started", () => {
    expect(pick([mkBlock({ id: 1, blocked_at: iso(T - 5 * H24), expires_at: iso(now + 1) })])).toBe(1);
    expect(pick([mkBlock({ id: 1, blocked_at: iso(now + H24), expires_at: iso(now + 2 * H24) })])).toBe(1);
  });
  it("no end means in force", () => {
    expect(pick([mkBlock({ expires_at: null })])).toBe(1);
  });
  it("ignores other sensors, other ips, inactive, and ended blocks", () => {
    expect(pick([
      mkBlock({ id: 1, sensor_id: 9 }), mkBlock({ id: 2, ip: "9.9.9.9" }),
      mkBlock({ id: 3, active: false }), mkBlock({ id: 4, expires_at: iso(now) }),
      mkBlock({ id: 5, expires_at: iso(now + 5000), unblocked_at: iso(now - 1) }),
    ])).toBeUndefined();
  });
});

describe("timeline", () => {
  const texts = (items: { text: unknown }[]) => items.map((i) => i.text);
  it("lists flow then scored, sorted by time", () => {
    const items = timeline(mkAlert(), [], T + 10);
    expect(texts(items)).toEqual([
      "flow seen: TCP 10.0.0.1:1234 → 10.0.0.2:80",
      "scored PortScan 95.00%, explained (SHAP)",
    ]);
  });
  it("omits the explained part without a method", () => {
    const items = timeline(mkAlert({ explanation: {} }), [], T);
    expect(texts(items)[1]).toBe("scored PortScan 95.00%");
  });
  it("adds block events in time order: unblocked, expired, ends", () => {
    const now = T + 10_000_000;
    const items = timeline(mkAlert(), [
      mkBlock({ id: 1, blocked_at: iso(T + 5000), unblocked_at: iso(T + 9000), reason: "r1" }),
      mkBlock({ id: 2, blocked_at: iso(T + 6000), expires_at: iso(now - 1), reason: "r2", source: "analyst" }),
      mkBlock({ id: 3, blocked_at: iso(T + 7000), expires_at: iso(now + 1000), reason: "r3" }),
    ], now);
    expect(texts(items)).toEqual([
      "flow seen: TCP 10.0.0.1:1234 → 10.0.0.2:80",
      "10.0.0.1 blocked (auto): r1",
      "10.0.0.1 blocked (analyst): r2",
      "10.0.0.1 blocked (auto): r3",
      "unblocked",
      "scored PortScan 95.00%, explained (SHAP)",
      "block expired by itself",
      "block ends",
    ]);
  });
  it("labels blocks already in force and later blocks, but not the alert's own", () => {
    const items = timeline(mkAlert(), [
      mkBlock({ id: 1, blocked_at: iso(T - 1000), reason: "old" }),
      mkBlock({ id: 2, blocked_at: iso(T - 1000), alert_id: 7, reason: "own" }),
      mkBlock({ id: 3, blocked_at: iso(T + 120_000), reason: "later" }),
      mkBlock({ id: 4, blocked_at: iso(T + 5000), reason: "during" }),
    ], T);
    const t = texts(items);
    expect(t).toContain("10.0.0.1 blocked (auto) (already in force): old");
    expect(t).toContain("10.0.0.1 blocked (auto): own");
    expect(t).toContain("10.0.0.1 blocked (auto) (later block of this address): later");
    expect(t).toContain("10.0.0.1 blocked (auto): during");
  });
  it("includes the date for events not on the received day", () => {
    const items = timeline(mkAlert(), [mkBlock({ id: 1, blocked_at: iso(T + 3 * H24), expires_at: null })], T);
    const at = (text: string) => items.find((i) => String(i.text).startsWith(text))!.at;
    expect(at("scored")).toBe(new Date(T + 60_000).toLocaleTimeString());
    expect(at("flow")).toBe(new Date(T).toLocaleTimeString());
    expect(at("10.0.0.1 blocked")).toBe(new Date(T + 3 * H24).toLocaleString());
  });
  it("expiry exactly now counts as expired", () => {
    const items = timeline(mkAlert(), [mkBlock({ expires_at: iso(T + 20_000) })], T + 20_000);
    expect(texts(items)).toContain("block expired by itself");
  });
});

// ---- page ----
let alert: Record<string, unknown>;
let blocks: unknown[];
let blocksError: Error | null;
let cases: unknown[];
let gates: Record<string, Promise<void>>;
let patchGate: Promise<void> | null;
const future = () => iso(Date.now() + 3600_000);

const calls = (method: string, prefix = "") =>
  h.api.mock.calls.filter(([p, o]) => (o?.method ?? "GET") === method && String(p).startsWith(prefix));

beforeEach(() => {
  alert = mkAlert() as never;
  blocks = [];
  blocksError = null;
  cases = [{ id: 5, title: "Case A" }];
  gates = {};
  patchGate = null;
  h.live = null;
  h.api.mockReset();
  h.api.mockImplementation(async (path: string, opts?: { method?: string; json?: Record<string, unknown> }) => {
    const m = opts?.method ?? "GET";
    if (m === "PATCH") { if (patchGate) await patchGate; return { ...alert, ...opts!.json }; }
    if (m === "POST" && path === "/cases") return { id: 8 };
    if (m === "POST" && path.endsWith("/alerts")) return { id: Number(path.split("/")[2]) };
    if (path.startsWith("/blocks")) {
      if (blocksError) throw blocksError;
      return { items: blocks, total: blocks.length };
    }
    if (path.startsWith("/cases")) return { items: cases, total: cases.length };
    if (path === "/alerts/0") throw new Error("not found");
    const mm = /^\/alerts\/(\d+)$/.exec(path);
    if (mm) {
      const g = gates[mm[1]] as Promise<void> | undefined;
      if (g) await g;
      return mm[1] === "7" ? alert : { ...(alert as object), id: Number(mm[1]), predicted_class: "DoS", case_id: null };
    }
    throw new Error(`unexpected ${path}`);
  });
});

const show = (url = "/alerts/7") =>
  render(<MemoryRouter initialEntries={[url]}><Routes><Route path="/alerts/:id" element={<AlertDetail />} /></Routes></MemoryRouter>);
const loaded = () => screen.findByRole("heading", { level: 1 });

describe("AlertDetail page", () => {
  it("heading, severity, neutral confidence pill; blocked pill only for an active, unexpired same-sensor block", async () => {
    blocks = [mkBlock({ id: 1, sensor_id: 9, expires_at: future() })];
    const { unmount } = show();
    expect(await loaded()).toHaveTextContent("PortScan · alert #7");
    expect(screen.getByText(/high/i)).toBeInTheDocument();
    const conf = screen.getByText("confidence 95.0%");
    expect(conf).toHaveClass("pill", "neutral");
    expect(conf).not.toHaveClass("ok");
    await screen.findByText(/No block of 10.0.0.1/);
    expect(screen.queryByText(/source blocked/)).toBeNull();
    expect(screen.getByRole("link", { name: "Block source IP…" })).toBeInTheDocument();
    unmount();

    blocks = [mkBlock({ id: 1, sensor_id: 9 }), mkBlock({ id: 2, expires_at: future() })];
    show();
    expect(await screen.findByText("source blocked · auto")).toBeInTheDocument();
  });

  it("a block that began before the flow still shows the pill and the Triage text instead of the link", async () => {
    const until = future();
    blocks = [mkBlock({ blocked_at: iso(T - 5 * H24), expires_at: until, source: "analyst" })];
    show();
    expect(await screen.findByText("source blocked · analyst")).toBeInTheDocument();
    const p = screen.getByText(/is blocked on sensor #3/);
    expect(p).toHaveTextContent(/^10\.0\.0\.1 is blocked on sensor #3 until .+\. See it on Response$/);
    expect(within(p).getByRole("link", { name: "See it on Response" })).toHaveAttribute("href", "/response");
    expect(screen.queryByRole("link", { name: "Block source IP…" })).toBeNull();
  });

  it("the pill disappears when the block's expiry passes (15 s clock)", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    try {
      blocks = [mkBlock({ blocked_at: iso(Date.now() - 1000), expires_at: iso(Date.now() + 20_000) })];
      show();
      expect(await screen.findByText("source blocked · auto")).toBeInTheDocument();
      await act(async () => {}); // flush passive effects so the useNow interval exists
      act(() => { vi.advanceTimersByTime(30_000); });
      expect(screen.queryByText(/source blocked/)).toBeNull();
      expect(screen.getByRole("link", { name: "Block source IP…" })).toBeInTheDocument();
    } finally { vi.useRealTimers(); }
  });

  it("refreshes blocks through useLiveRefresh every 30 s", async () => {
    show();
    await loaded();
    await screen.findByText(/No block of/);
    expect(h.live!.ms).toBe(30_000);
    expect(calls("GET", "/blocks").length).toBe(1);
    blocks = [mkBlock({ expires_at: future() })];
    act(() => { h.live!.fn(); });
    expect(await screen.findByText("source blocked · auto")).toBeInTheDocument();
    expect(calls("GET", "/blocks").length).toBe(2);
  });

  it("two quick status clicks send one PATCH and the buttons are disabled meanwhile", async () => {
    let release!: () => void;
    patchGate = new Promise<void>((r) => { release = r; });
    show();
    await loaded();
    const group = within(screen.getByRole("group", { name: "Status" }));
    const other = ALERT_STATUSES.find((s) => s !== "new")!;
    fireEvent.click(group.getByRole("button", { name: label(other) }));
    await waitFor(() => expect(group.getByRole("button", { name: label("new") })).toBeDisabled());
    fireEvent.click(group.getByRole("button", { name: label(other) }));
    release();
    await waitFor(() => expect(group.getByRole("button", { name: label(other) })).toBeEnabled());
    expect(calls("PATCH").length).toBe(1);
  });

  it("flow time shows a date for an end on another day", async () => {
    alert = mkAlert({ end_ms: T + 2 * H24 }) as never;
    show();
    await loaded();
    expect(screen.getByText(new RegExp(new Date(T + 2 * H24).toLocaleString().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")))).toBeInTheDocument();
  });

  it("navigating to another alert clears notice and case and never shows the old data while loading", async () => {
    function Nav() { const n = useNavigate(); return <button onClick={() => n("/alerts/2")}>next</button>; }
    render(<MemoryRouter initialEntries={["/alerts/7"]}>
      <Routes><Route path="/alerts/:id" element={<AlertDetail />} /></Routes><Nav />
    </MemoryRouter>);
    await loaded();
    fireEvent.change(screen.getByLabelText("Add to open case"), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await screen.findByText("Added to case #5.");
    let release!: () => void;
    gates["2"] = new Promise<void>((r) => { release = r; });
    fireEvent.click(screen.getByText("next"));
    expect(await screen.findByText("Loading…")).toBeInTheDocument();
    expect(screen.queryByText(/PortScan · alert #7/)).toBeNull();
    release();
    expect(await screen.findByRole("heading", { level: 1, name: "DoS · alert #2" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
    expect(screen.getByLabelText("Add to open case")).toHaveValue("");
  });

  it("an ended block gives no blocked pill", async () => {
    blocks = [mkBlock({ active: false, unblocked_at: iso(T + 9000) })];
    show();
    await loaded();
    await screen.findByText("unblocked");
    expect(screen.queryByText(/source blocked/)).toBeNull();
  });

  it("a non-numeric id requests /alerts/0, never the raw string", async () => {
    show("/alerts/abc");
    expect(await screen.findByText("not found")).toBeInTheDocument();
    const paths = h.api.mock.calls.map(([p]) => String(p));
    expect(paths).toContain("/alerts/0");
    expect(paths.some((p) => p.includes("abc"))).toBe(false);
  });

  it("links to all alerts from the IP, the assistant, and shows the sensor", async () => {
    show();
    await loaded();
    expect(screen.getByRole("link", { name: "all alerts involving this IP" })).toHaveAttribute("href", "/alerts?ip=10.0.0.1");
    expect(screen.getByRole("link", { name: "Explain this alert with the assistant" })).toHaveAttribute("href", "/assistant?alert=7");
  });

  it("shows the receive delay, and nothing for a negative gap", async () => {
    alert = mkAlert({ received_at: iso(T + 1000 + 120_000) }) as never;
    const { unmount } = show();
    expect(await screen.findByText("(+2 min after the flow ended)")).toBeInTheDocument();
    unmount();
    alert = mkAlert({ received_at: iso(T + 500) }) as never;
    show();
    await loaded();
    expect(screen.queryByText(/after the flow ended/)).toBeNull();
  });

  it("status buttons: aria-pressed, PATCH on change, nothing for the current one", async () => {
    show();
    await loaded();
    const group = within(screen.getByRole("group", { name: "Status" }));
    const [cur, other] = [ALERT_STATUSES[0], ALERT_STATUSES.find((s) => s !== "new")!];
    expect(alert.status).toBe("new");
    expect(group.getByRole("button", { name: label("new") })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(group.getByRole("button", { name: label(cur) }));
    expect(calls("PATCH").length).toBe(0);
    fireEvent.click(group.getByRole("button", { name: label(other) }));
    await waitFor(() => expect(calls("PATCH").length).toBe(1));
    expect(calls("PATCH")[0][0]).toBe("/alerts/7");
    expect(calls("PATCH")[0][1].json).toEqual({ status: other });
    await waitFor(() => expect(group.getByRole("button", { name: label(other) })).toHaveAttribute("aria-pressed", "true"));
    expect(group.getByRole("button", { name: label("new") })).toHaveAttribute("aria-pressed", "false");
  });

  it("Block source IP is an encoded link and posts nothing", async () => {
    show();
    await loaded();
    const link = screen.getByRole("link", { name: "Block source IP…" });
    expect(link).toHaveAttribute("href", "/response?ip=10.0.0.1&sensor=3&reason=alert+%237%3A+PortScan");
    fireEvent.click(link);
    expect(calls("POST").length).toBe(0);
  });

  it("add to an open case", async () => {
    show();
    await loaded();
    const add = screen.getByRole("button", { name: "Add" });
    expect(add).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Add to open case"), { target: { value: "5" } });
    fireEvent.click(add);
    await waitFor(() => expect(calls("POST", "/cases/5/alerts").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ alert_ids: [7] });
    expect(await screen.findByRole("link", { name: "case #5" })).toHaveAttribute("href", "/cases/5");
    expect(screen.getByRole("link", { name: "case #5" }).parentElement).toHaveTextContent("In case #5.");
    expect(screen.getByRole("status")).toHaveTextContent("Added to case #5.");
    expect(screen.queryByRole("button", { name: "Add" })).toBeNull();
  });

  it("create a case with a trimmed title", async () => {
    show();
    await loaded();
    const create = screen.getByRole("button", { name: "Create" });
    expect(create).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Or open a new case"), { target: { value: "  Scan wave  " } });
    fireEvent.click(create);
    await waitFor(() => expect(calls("POST", "/cases").length).toBe(1));
    expect(calls("POST")[0][1].json).toEqual({ title: "Scan wave", alert_ids: [7] });
    expect(await screen.findByText(/^In/)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Created case #8.");
  });

  it("hides case controls when the alert already has a case", async () => {
    alert = mkAlert({ case_id: 4 }) as never;
    show();
    await loaded();
    expect(screen.queryByLabelText("Add to open case")).toBeNull();
    expect(screen.queryByRole("button", { name: "Create" })).toBeNull();
    expect(screen.getAllByRole("link", { name: /case #4|#4/ }).length).toBeGreaterThan(0);
  });

  it("what happened: empty message, blocks request, and an error", async () => {
    const { unmount } = show();
    expect(await screen.findByText("No block of 10.0.0.1 on this sensor around this alert.")).toBeInTheDocument();
    expect(calls("GET", "/blocks?ip=10.0.0.1&limit=100").length).toBe(1);
    expect(calls("GET", "/cases?status=open&limit=100").length).toBe(1);
    unmount();
    blocksError = new Error("blocks down");
    show();
    expect(await screen.findByText("blocks down")).toBeInTheDocument();
    expect(screen.queryByText(/No block of/)).toBeNull();
  });

  it("renders untrusted text as text", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    alert = mkAlert({
      predicted_class: evil,
      explanation: { method: "shap", predicted_class: evil, top_features: [{ feature: evil, value: 1, contribution: 1 }] },
    }) as never;
    blocks = [mkBlock({ reason: evil })];
    const { container } = show();
    await loaded();
    await screen.findByText(new RegExp("blocked \\(auto\\)"));
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(evil);
    expect(container.textContent).toContain(`blocked (auto): ${evil}`);
  });
});

describe("ExplanationChart summary", () => {
  const norm = (c: HTMLElement) => c.textContent!.replace(/\s+/g, " ");
  const feats = [
    { feature: "a", value: 1, contribution: 0.5 },
    { feature: "b", value: 2, contribution: -0.5 },
  ];
  it("shows the summary with base value and confidence", () => {
    const { container } = render(<ExplanationChart explanation={{
      method: "shap", predicted_class: "PortScan", base_value: 0.1234, confidence: 0.9999, output_space: "log_odds", top_features: feats,
    }} />);
    expect(norm(container)).toContain("SHAP: top 2 features behind the decision for PortScan.");
    expect(norm(container)).toContain("Contributions in log odds. Base value 0.123 → confidence 99.99%.");
    expect(norm(container)).toContain("pushes towards PortScan");
    expect(norm(container)).toContain("pushes away");
  });
  it("shows the output space even without a base value", () => {
    const { container } = render(<ExplanationChart explanation={{
      method: "lime", predicted_class: "PortScan", output_space: "probability", top_features: feats,
    }} />);
    expect(norm(container)).toContain("LIME: top 2 features behind the decision for PortScan. Contributions in probability.");
    expect(norm(container)).not.toContain("Base value");
  });
  it("omits the base part without base_value", () => {
    const { container } = render(<ExplanationChart explanation={{
      method: "shap", predicted_class: "PortScan", confidence: 0.9999, top_features: feats,
    }} />);
    expect(norm(container)).toContain("SHAP: top 2 features behind the decision for PortScan.");
    expect(norm(container)).not.toContain("Base value");
    expect(norm(container)).not.toContain("confidence 99.99%");
  });
});
