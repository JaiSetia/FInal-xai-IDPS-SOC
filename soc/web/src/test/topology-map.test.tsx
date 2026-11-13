import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import TopologyMap, { edgeWidth, limitGraph, roleOf } from "../pages/TopologyMap";

const h = vi.hoisted(() => ({
  api: vi.fn(), sim: vi.fn(), live: [] as { fn: () => void; ms: number | undefined }[],
  flow: null as null | Record<string, unknown>,
  nodes: [] as { id: string; selected?: boolean }[],
}));
vi.mock("d3-force", async (orig) => {
  const m = await orig<typeof import("d3-force")>();
  return { ...m, forceSimulation: ((...a: Parameters<typeof m.forceSimulation>) => { h.sim(); return m.forceSimulation(...a); }) as typeof m.forceSimulation };
});
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (fn: () => void, _a: unknown, ms?: number) => { h.live.push({ fn, ms }); return true; },
}));
vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ nodes, onNodeClick, onPaneClick, children, ...rest }: {
    nodes: { id: string; selected?: boolean; ariaLabel?: string; data: { label: ReactNode } }[];
    onNodeClick: (e: unknown, n: unknown) => void; onPaneClick: () => void; children?: ReactNode;
    [k: string]: unknown;
  }) => {
    h.flow = rest;
    h.nodes = nodes;
    return (
    <div data-testid="flow" onClick={onPaneClick}>
      {nodes.map((n) => (
        <div key={n.id} className="react-flow__node" data-id={n.id} tabIndex={0} aria-label={n.ariaLabel}
          onKeyDown={(e) => {
            // React Flow blurs a host on the next frame when its selection toggles.
            if (e.key === "Enter" || e.key === " " || e.key === "Escape") {
              const el = e.currentTarget;
              requestAnimationFrame(() => el.blur());
            }
          }}
          onClick={(e) => { e.stopPropagation(); onNodeClick(e, n); }}>{n.data.label}</div>
      ))}
      {children}
    </div>
    );
  },
  Background: () => <div data-testid="bg" tabIndex={0} />,
  Controls: () => null,
  MarkerType: { ArrowClosed: "arrowclosed" },
}));

const topo = {
  hours: 24,
  nodes: [
    { ip: "10.0.0.1", alert_count: 5, max_severity: "high" },
    { ip: "10.0.0.2", alert_count: 3, max_severity: "medium" },
    { ip: "10.0.0.3", alert_count: 1, max_severity: "low" },
    { ip: "10.0.0.9", alert_count: 2, max_severity: "critical" },
  ],
  edges: [
    { src: "10.0.0.1", dst: "10.0.0.2", count: 3, max_severity: "medium" },
    { src: "10.0.0.1", dst: "10.0.0.3", count: 1, max_severity: "low" },
    { src: "10.0.0.9", dst: "10.0.0.1", count: 2, max_severity: "critical" },
  ],
};

let topology: unknown;
let blocks: unknown[];
let blocksError: Error | null;
let alertItems: unknown[];
const calls = (prefix: string) => h.api.mock.calls.filter(([p]) => String(p).startsWith(prefix));

beforeEach(() => {
  topology = topo;
  blocks = [];
  blocksError = null;
  alertItems = [{ id: 1, sensor_id: 4 }];
  h.sim.mockClear();
  h.live = [];
  h.flow = null;
  h.api.mockReset();
  h.api.mockImplementation(async (path: string) => {
    if (path.startsWith("/topology")) return topology;
    if (path.startsWith("/alerts?ip=")) return { items: alertItems, total: alertItems.length };
    if (path.startsWith("/blocks?ip=")) {
      if (blocksError) throw blocksError;
      return { items: blocks, total: blocks.length };
    }
    throw new Error(`unexpected ${path}`);
  });
});

const onShowWorld = vi.fn();
const ui = (hours = 24) => (
  <MemoryRouter><TopologyMap hours={hours} onShowWorld={onShowWorld} /></MemoryRouter>
);
const show = (hours = 24) => render(ui(hours));
const node = (ip: string) => document.querySelector<HTMLElement>(`.react-flow__node[data-id="${ip}"]`)!;
const select = async (ip: string) => {
  await screen.findByLabelText(new RegExp(`^${ip.replace(/\./g, "\\.")},`));
  fireEvent.click(node(ip));
  return screen.findByLabelText(`Selected host ${ip}`);
};

describe("roleOf", () => {
  const edges = [{ src: "a", dst: "b" }, { src: "c", dst: "a" }] as never;
  it("source, target, both", () => {
    expect(roleOf("c", edges)).toBe("source");
    expect(roleOf("b", edges)).toBe("target");
    expect(roleOf("a", edges)).toBe("both");
  });
});

describe("edgeWidth", () => {
  it("is 1.5 at 0 and 6 at max", () => {
    expect(edgeWidth(0, 10)).toBe(1.5);
    expect(edgeWidth(10, 10)).toBe(6);
  });
  it("is monotonic", () => {
    const w = [0, 1, 2, 5, 9, 10].map((c) => edgeWidth(c, 10));
    for (let i = 1; i < w.length; i++) expect(w[i]).toBeGreaterThan(w[i - 1]);
  });
  it("is safe with max 0 and negative counts", () => {
    expect(Number.isFinite(edgeWidth(0, 0))).toBe(true);
    expect(edgeWidth(0, 0)).toBe(1.5);
    expect(edgeWidth(-3, 0)).toBe(1.5);
  });
});

describe("limitGraph", () => {
  const big = {
    hours: 1,
    nodes: [
      { ip: "a", alert_count: 1, max_severity: "low" }, { ip: "b", alert_count: 9, max_severity: "high" },
      { ip: "c", alert_count: 5, max_severity: "low" }, { ip: "d", alert_count: 7, max_severity: "low" },
    ],
    edges: [
      { src: "b", dst: "d", count: 2, max_severity: "low" }, { src: "a", dst: "b", count: 1, max_severity: "low" },
      { src: "c", dst: "d", count: 1, max_severity: "low" }, { src: "b", dst: "c", count: 1, max_severity: "low" },
    ],
  } as never;
  it("keeps the busiest nodes and only edges between them", () => {
    const { graph, hidden } = limitGraph(big, 2);
    expect(graph.nodes.map((n: { ip: string }) => n.ip)).toEqual(["b", "d"]);
    expect(graph.edges).toEqual([{ src: "b", dst: "d", count: 2, max_severity: "low" }]);
    expect(hidden).toBe(2);
  });
  it("is unchanged at or under the limit", () => {
    for (const max of [4, 10]) {
      const r = limitGraph(big, max);
      expect(r.graph).toBe(big);
      expect(r.hidden).toBe(0);
    }
  });
  it("defaults to 150", () => {
    const nodes = Array.from({ length: 153 }, (_, i) => ({ ip: `n${i}`, alert_count: i, max_severity: "low" }));
    const r = limitGraph({ hours: 1, nodes, edges: [] } as never);
    expect(r.graph.nodes.length).toBe(150);
    expect(r.hidden).toBe(3);
    expect(r.graph.nodes.some((n: { ip: string }) => n.ip === "n0")).toBe(false);
  });
});

describe("TopologyMap", () => {
  it("tells how many hosts are left out beyond 150", async () => {
    topology = {
      hours: 24,
      nodes: Array.from({ length: 152 }, (_, i) => ({ ip: `10.1.${i >> 8}.${i & 255}`, alert_count: i + 1, max_severity: "low" })),
      edges: [],
    };
    show();
    expect(await screen.findByText(/Showing the 150 busiest hosts; 2 more are left out\./)).toBeInTheDocument();
    expect(document.querySelectorAll(".react-flow__node").length).toBe(150);
  });

  it("shows no left-out note under the limit", async () => {
    show();
    await screen.findByLabelText(/^10\.0\.0\.1,/);
    expect(screen.queryByText(/busiest hosts/)).toBeNull();
  });

  it("lays out only when the hosts or links change", async () => {
    show();
    await screen.findByLabelText(/^10\.0\.0\.1,/);
    expect(h.sim).toHaveBeenCalledTimes(1);
    const reload = h.live.find((l) => l.ms === undefined)!.fn;
    // the same graph again (a new object, reordered nodes): no new layout
    topology = { ...topo, nodes: [...topo.nodes].reverse(), edges: [...topo.edges].reverse() };
    act(() => { reload(); });
    await waitFor(() => expect(calls("/topology").length).toBe(2));
    await act(async () => {});
    expect(h.sim).toHaveBeenCalledTimes(1);
    // a counts-only change: still the same shape
    topology = { ...topo, nodes: topo.nodes.map((n) => ({ ...n, alert_count: n.alert_count + 1 })) };
    act(() => { reload(); });
    await waitFor(() => expect(calls("/topology").length).toBe(3));
    await act(async () => {});
    expect(h.sim).toHaveBeenCalledTimes(1);
    // a new host: layout runs again
    topology = { ...topo, nodes: [...topo.nodes, { ip: "10.0.0.50", alert_count: 1, max_severity: "low" }] };
    act(() => { reload(); });
    await screen.findByLabelText(/^10\.0\.0\.50,/);
    expect(h.sim).toHaveBeenCalledTimes(2);
  });

  it("makes nodes not draggable and edges not focusable", async () => {
    show();
    await screen.findByLabelText(/^10\.0\.0\.1,/);
    expect(h.flow).toMatchObject({ nodesDraggable: false, edgesFocusable: false, nodesConnectable: false });
  });

  it("legend has a both entry and a severity key", async () => {
    const { container } = show();
    await screen.findByLabelText(/^10\.0\.0\.1,/);
    expect(screen.getByText("both")).toBeInTheDocument();
    expect(Array.from(container.querySelectorAll(".sev-key")).map((e) => e.textContent)).toEqual(["low", "medium", "high", "critical"]);
  });

  it("requests /topology with the hours and again when they change", async () => {
    const { rerender } = show(24);
    await screen.findByLabelText(/^10\.0\.0\.1,/);
    expect(calls("/topology").map(([p]) => p)).toEqual(["/topology?hours=24"]);
    rerender(ui(6));
    await waitFor(() => expect(calls("/topology").map(([p]) => p)).toEqual(["/topology?hours=24", "/topology?hours=6"]));
  });

  it("labels nodes for assistive technology", async () => {
    show();
    expect(await screen.findByLabelText("10.0.0.9, source of alerts, 2 alerts, highest severity critical")).toBeInTheDocument();
    expect(screen.getByLabelText("10.0.0.2, target of alerts, 3 alerts, highest severity medium")).toBeInTheDocument();
    expect(screen.getByLabelText("10.0.0.1, source and target of alerts, 5 alerts, highest severity high")).toBeInTheDocument();
  });

  it("says so for an empty topology", async () => {
    topology = { hours: 24, nodes: [], edges: [] };
    show();
    expect(await screen.findByText("No alerts in this window.")).toBeInTheDocument();
    expect(screen.queryByTestId("flow")).toBeNull();
  });

  it("shows the placeholder until a node is clicked", async () => {
    show();
    await screen.findByLabelText(/^10\.0\.0\.1,/);
    expect(screen.getByText("Click a host to see who it talks to.")).toBeInTheDocument();
    await select("10.0.0.1");
    expect(screen.queryByText("Click a host to see who it talks to.")).toBeNull();
  });

  it("shows a host's details: role, counts, severity, flows, alerts link", async () => {
    show();
    const panel = within(await select("10.0.0.1"));
    expect(screen.getByLabelText("Selected host 10.0.0.1")).toHaveTextContent("Selected: 10.0.0.1");
    expect(panel.getByText("source and target of alerts")).toBeInTheDocument();
    expect(panel.getByText("Targets").nextSibling).toHaveTextContent("2 hosts");
    expect(panel.getByText("Sources").nextSibling).toHaveTextContent("1 host");
    expect(panel.getByText("Alerts").nextSibling).toHaveTextContent("5");
    expect(panel.getByText("high")).toHaveClass("badge");
    const flows = within(panel.getByRole("list", { name: "Flows" })).getAllByRole("listitem").map((li) => li.textContent);
    expect(flows).toEqual(["→ 10.0.0.23 alerts", "→ 10.0.0.31 alert", "← 10.0.0.92 alerts"]);
    expect(panel.getByRole("link", { name: "Show its alerts" })).toHaveAttribute("href", "/alerts?ip=10.0.0.1");
  });

  it("singular host for one peer", async () => {
    show();
    const panel = within(await select("10.0.0.9"));
    expect(panel.getByText("Targets").nextSibling).toHaveTextContent("1 host");
    expect(panel.queryByText("Sources")).toBeNull();
  });

  describe("block state", () => {
    it("a source without an active block gets an encoded Block link with the newest alert's sensor", async () => {
      show();
      const panel = within(await select("10.0.0.9"));
      await waitFor(() => expect(panel.getByRole("link", { name: "Block…" }))
        .toHaveAttribute("href", "/response?ip=10.0.0.9&sensor=4&sensor_guess=1&from=topology&count=2&hours=24"));
      expect(calls("/alerts?ip=10.0.0.9&limit=1").length).toBe(1);
      expect(calls("/blocks?ip=10.0.0.9&active=true&limit=20").length).toBe(1);
      expect(await panel.findByText("none active")).toBeInTheDocument();
    });

    it("without a found sensor the link has neither sensor nor sensor_guess", async () => {
      alertItems = [];
      show();
      const panel = within(await select("10.0.0.9"));
      await waitFor(() => expect(panel.queryByText("Looking up its sensor…")).toBeNull());
      expect(panel.getByRole("link", { name: "Block…" }))
        .toHaveAttribute("href", "/response?ip=10.0.0.9&from=topology&count=2&hours=24");
    });

    it("refreshes the block state through useLiveRefresh every 30 s", async () => {
      show();
      const panel = within(await select("10.0.0.9"));
      await panel.findByText("none active");
      const host = h.live.filter((l) => l.ms === 30_000).at(-1)!;
      expect(host).toBeDefined();
      expect(calls("/blocks?ip=10.0.0.9").length).toBe(1);
      blocks = [{ id: 1, ip: "10.0.0.9", sensor_id: 2, active: true, expires_at: null }];
      act(() => { host.fn(); });
      expect(await panel.findByText("sensor #2")).toBeInTheDocument();
      expect(calls("/blocks?ip=10.0.0.9").length).toBe(2);
    });

    it("uses the hours prop in the link", async () => {
      show(6);
      const panel = within(await select("10.0.0.9"));
      await waitFor(() => expect(panel.getByRole("link", { name: "Block…" }))
        .toHaveAttribute("href", expect.stringContaining("from=topology&count=2&hours=6")));
    });

    it("the Block link never carries a reason", async () => {
      show();
      const panel = within(await select("10.0.0.9"));
      const link = await waitFor(() => panel.getByRole("link", { name: "Block…" }));
      expect(link.getAttribute("href")).not.toContain("reason");
    });

    it("a pure target has no Block link", async () => {
      show();
      const panel = within(await select("10.0.0.2"));
      await panel.findByText("none active");
      expect(panel.queryByRole("link", { name: "Block…" })).toBeNull();
      expect(panel.getByRole("link", { name: "Show its alerts" })).toBeInTheDocument();
    });

    it("an active block shows sensor and expiry and hides the Block link", async () => {
      blocks = [{ id: 1, ip: "10.0.0.9", sensor_id: 2, active: true, expires_at: new Date(Date.now() + 3600_000).toISOString() }];
      show();
      const panel = within(await select("10.0.0.9"));
      expect(await panel.findByText(/^sensor #2 until /)).toBeInTheDocument();
      expect(panel.queryByRole("link", { name: "Block…" })).toBeNull();
    });

    it("a blocks error shows unknown", async () => {
      blocksError = new Error("nope");
      show();
      const panel = within(await select("10.0.0.9"));
      expect(await panel.findByText("unknown")).toBeInTheDocument();
    });
  });

  describe("keyboard", () => {
    it.each(["Enter", " "])("pressing %j on a focused node selects it", async (key) => {
      show();
      await screen.findByLabelText(/^10\.0\.0\.2,/);
      const n = node("10.0.0.2");
      n.focus();
      fireEvent.keyDown(n, { key });
      expect(await screen.findByLabelText("Selected host 10.0.0.2")).toBeInTheDocument();
    });

    it("other keys do nothing", async () => {
      show();
      await screen.findByLabelText(/^10\.0\.0\.2,/);
      fireEvent.keyDown(node("10.0.0.2"), { key: "a" });
      expect(screen.getByText("Click a host to see who it talks to.")).toBeInTheDocument();
    });

    it("Escape clears the selection", async () => {
      show();
      await select("10.0.0.2");
      fireEvent.keyDown(node("10.0.0.2"), { key: "Escape" });
      expect(screen.getByText("Click a host to see who it talks to.")).toBeInTheDocument();
      expect(screen.queryByLabelText("Selected host 10.0.0.2")).toBeNull();
    });

    it("Enter on something that is not a node does nothing", async () => {
      show();
      await screen.findByLabelText(/^10\.0\.0\.2,/);
      fireEvent.keyDown(screen.getByTestId("bg"), { key: "Enter" });
      expect(screen.getByText("Click a host to see who it talks to.")).toBeInTheDocument();
    });
  });

  describe("React Flow selection and keyboard focus", () => {
    afterEach(() => vi.useRealTimers());
    const frames = (n: number) => { for (let i = 0; i < n; i++) act(() => { vi.advanceTimersByTime(16); }); };
    const fakeFrames = () => vi.useFakeTimers({ toFake: ["requestAnimationFrame", "cancelAnimationFrame"] });
    // Let any async layout/refresh updates land first: a new `nodes` array cancels the refocus frames.
    const settle = () => act(async () => { await new Promise((r) => setTimeout(r, 60)); });
    const selectedIds = () => h.nodes.filter((n) => n.selected).map((n) => n.id);

    it("passes selected: true only for the selected host", async () => {
      show();
      await screen.findByLabelText(/^10\.0\.0\.1,/);
      expect(h.nodes.length).toBe(4);
      expect(selectedIds()).toEqual([]);
      fireEvent.click(node("10.0.0.2"));
      await screen.findByLabelText("Selected host 10.0.0.2");
      expect(selectedIds()).toEqual(["10.0.0.2"]);
      fireEvent.click(node("10.0.0.9"));
      await screen.findByLabelText("Selected host 10.0.0.9");
      expect(selectedIds()).toEqual(["10.0.0.9"]);
      fireEvent.click(screen.getByTestId("flow"));
      await screen.findByText("Click a host to see who it talks to.");
      expect(selectedIds()).toEqual([]);
    });

    it.each([["Enter"], [" "]])("focus returns to the host after %j", async (key) => {
      show();
      await screen.findByLabelText(/^10\.0\.0\.2,/);
      await settle();
      fakeFrames();
      const n = node("10.0.0.2");
      n.focus();
      expect(document.activeElement).toBe(n);
      fireEvent.keyDown(n, { key });
      await screen.findByLabelText("Selected host 10.0.0.2");
      frames(1);
      expect(document.activeElement).not.toBe(n); // the simulated React Flow blur
      frames(2);
      expect(document.activeElement).toBe(node("10.0.0.2"));
    });

    it("focus returns to the host after Escape", async () => {
      show();
      await screen.findByLabelText(/^10\.0\.0\.2,/);
      await settle();
      fakeFrames();
      const n = node("10.0.0.2");
      n.focus();
      fireEvent.keyDown(n, { key: "Enter" });
      await screen.findByLabelText("Selected host 10.0.0.2");
      frames(3);
      expect(document.activeElement).toBe(node("10.0.0.2"));
      fireEvent.keyDown(node("10.0.0.2"), { key: "Escape" });
      await screen.findByText("Click a host to see who it talks to.");
      frames(1);
      expect(document.activeElement).not.toBe(node("10.0.0.2"));
      frames(2);
      expect(document.activeElement).toBe(node("10.0.0.2"));
      expect(selectedIds()).toEqual([]);
    });

    it("a mouse click selection does not move focus", async () => {
      show();
      await screen.findByLabelText(/^10\.0\.0\.2,/);
      await settle();
      fakeFrames();
      const other = screen.getByRole("button", { name: "Open the world map" });
      other.focus();
      fireEvent.click(node("10.0.0.2"));
      await screen.findByLabelText("Selected host 10.0.0.2");
      frames(4);
      expect(document.activeElement).toBe(other);
    });

    describe("refocus is only for a real selection change", () => {
      const refresh = async () => {
        const reload = h.live.find((l) => l.ms === undefined)!.fn;
        topology = { ...topo, nodes: topo.nodes.map((n) => ({ ...n })) }; // a new data object, so new nodes
        await act(async () => { reload(); await new Promise((r) => setTimeout(r, 20)); });
      };
      const ready = async () => {
        show();
        await screen.findByLabelText(/^10\.0\.0\.2,/);
        await settle();
      };

      it("Escape with nothing selected, then a refresh: focus does not move", async () => {
        await ready();
        fakeFrames();
        const n = node("10.0.0.2");
        n.focus();
        fireEvent.keyDown(n, { key: "Escape" });
        frames(1); // the simulated React Flow blur
        expect(document.activeElement).toBe(document.body);
        await refresh();
        frames(5);
        expect(document.activeElement).toBe(document.body);
      });

      it("Enter on the already-selected host, then a refresh: no focus jump", async () => {
        await ready();
        fakeFrames();
        fireEvent.click(node("10.0.0.2"));
        await screen.findByLabelText("Selected host 10.0.0.2");
        frames(5);
        const n = node("10.0.0.2");
        n.focus();
        fireEvent.keyDown(n, { key: "Enter" });
        frames(1);
        expect(document.activeElement).toBe(document.body);
        await refresh();
        frames(5);
        expect(document.activeElement).toBe(document.body);
        expect(screen.getByLabelText("Selected host 10.0.0.2")).toBeInTheDocument();
      });

      it("a key press that changes nothing clears an earlier pending refocus", async () => {
        await ready();
        fakeFrames();
        const n = node("10.0.0.2");
        n.focus();
        fireEvent.keyDown(n, { key: "Enter" }); // requests a refocus
        await screen.findByLabelText("Selected host 10.0.0.2");
        fireEvent.keyDown(node("10.0.0.2"), { key: "Enter" }); // already selected: clears it
        frames(1);
        await refresh();
        frames(5);
        expect(document.activeElement).toBe(document.body);
      });

      it("focus moved to the side panel before the frames is not pulled back", async () => {
        await ready();
        fakeFrames();
        const n = node("10.0.0.2");
        n.focus();
        fireEvent.keyDown(n, { key: "Enter" });
        await screen.findByLabelText("Selected host 10.0.0.2");
        const panel = screen.getByRole("button", { name: "Open the world map" });
        panel.focus();
        frames(5);
        expect(document.activeElement).toBe(panel);
      });

      it("Escape with a selection still restores focus, also after a refresh in between", async () => {
        await ready();
        fakeFrames();
        const n = node("10.0.0.2");
        n.focus();
        fireEvent.keyDown(n, { key: "Enter" });
        await screen.findByLabelText("Selected host 10.0.0.2");
        frames(5);
        fireEvent.keyDown(node("10.0.0.2"), { key: "Escape" });
        await screen.findByText("Click a host to see who it talks to.");
        await refresh(); // the effect re-runs and must still refocus
        frames(5);
        expect(document.activeElement).toBe(node("10.0.0.2"));
      });
    });

    it("pending refocus frames are cancelled on unmount", async () => {
      const { unmount } = show();
      await screen.findByLabelText(/^10\.0\.0\.2,/);
      await settle();
      fakeFrames();
      const n = node("10.0.0.2");
      n.focus();
      fireEvent.keyDown(n, { key: "Enter" });
      await screen.findByLabelText("Selected host 10.0.0.2");
      unmount();
      expect(() => frames(3)).not.toThrow();
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it("the world map button calls onShowWorld", async () => {
    onShowWorld.mockClear();
    show();
    fireEvent.click(screen.getByRole("button", { name: "Open the world map" }));
    expect(onShowWorld).toHaveBeenCalledTimes(1);
  });
});
