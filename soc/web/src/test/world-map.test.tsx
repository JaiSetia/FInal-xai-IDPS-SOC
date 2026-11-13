import { act, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import WorldMap from "../pages/WorldMap";

const h = vi.hoisted(() => ({ api: vi.fn(), onAlert: null as null | ((a: { src_ip: string }) => void), reload: null as null | (() => void) }));
vi.mock("../api/client", async (orig) => ({ ...(await orig<typeof import("../api/client")>()), api: h.api }));
vi.mock("../useLiveRefresh", () => ({
  useLiveRefresh: (f: () => void, onAlert: (a: { src_ip: string }) => void) => { h.onAlert = onAlert; h.reload = f; return true; },
}));

const geo = (o: Record<string, unknown> = {}) => ({
  hours: 6, home: null, geoip_status: "ok", demo: false, points: [], unlocated_sources: 0, ...o,
});

beforeEach(() => { h.api.mockReset(); h.api.mockResolvedValue(geo()); });

describe("WorldMap", () => {
  it("requests /geo/attacks with the hours prop", async () => {
    render(<WorldMap hours={6} />);
    await screen.findByText("Where attacks come from");
    expect(h.api.mock.calls.map(([p]) => p)).toEqual(["/geo/attacks?hours=6"]);
  });

  it("re-requests when the hours change", async () => {
    const { rerender } = render(<WorldMap hours={6} />);
    await screen.findByText("Where attacks come from");
    rerender(<WorldMap hours={72} />);
    await screen.findByText("Where attacks come from");
    expect(h.api.mock.calls.map(([p]) => p)).toContain("/geo/attacks?hours=72");
  });

  it("has no window select of its own", async () => {
    render(<WorldMap hours={6} />);
    await screen.findByText("Where attacks come from");
    expect(screen.queryByLabelText("Window")).toBeNull();
  });

  it("lists located sources and the map label", async () => {
    h.api.mockResolvedValue(geo({
      home: { lat: 50, lon: 8, label: "Lab" },
      points: [{ ip: "8.8.8.8", count: 3, max_severity: "high", lat: 37, lon: -122, country: "US", city: "Mountain View", source: "geoip" }],
    }));
    render(<WorldMap hours={6} />);
    expect(await screen.findByRole("img", { name: "World map of 1 attack sources" })).toBeInTheDocument();
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("Mountain View, US")).toBeInTheDocument();
    expect(screen.getByText("Lab")).toBeInTheDocument();
  });

  it("shows an API error", async () => {
    h.api.mockRejectedValue(new Error("geo down"));
    render(<WorldMap hours={6} />);
    expect(await screen.findByText("geo down")).toBeInTheDocument();
  });
});

describe("WorldMap hot arcs", () => {
  afterEach(() => vi.useRealTimers());

  it("clears its highlight timers on unmount", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const { unmount } = render(<WorldMap hours={6} />);
    await screen.findByText("Where attacks come from");
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    act(() => { h.onAlert!({ src_ip: "8.8.8.8" }); });
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
    expect(() => vi.advanceTimersByTime(4000)).not.toThrow();
    expect(err).not.toHaveBeenCalled();
    err.mockRestore();
  });

  it("the highlight timer is cleared by itself after 4 s while mounted", async () => {
    render(<WorldMap hours={6} />);
    await screen.findByText("Where attacks come from");
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    act(() => { h.onAlert!({ src_ip: "8.8.8.8" }); });
    expect(vi.getTimerCount()).toBe(1);
    act(() => { vi.advanceTimersByTime(4000); });
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("WorldMap compact", () => {
  const compact = (hours = 24) => render(<MemoryRouter><WorldMap hours={hours} compact /></MemoryRouter>);

  it("shows only the Live attack map card, no sources table", async () => {
    h.api.mockResolvedValue(geo({
      home: { lat: 50, lon: 8, label: "Lab" },
      points: [{ ip: "8.8.8.8", count: 3, max_severity: "high", lat: 37, lon: -122, country: "US", city: "MV", source: "geoip" }],
    }));
    compact();
    await screen.findByRole("img", { name: "World map of 1 attack sources" });
    expect(screen.getByText("Live attack map")).toBeInTheDocument();
    expect(screen.queryByText("Where attacks come from")).toBeNull();
    expect(screen.queryByText("Sources on the map")).toBeNull();
    expect(screen.queryByText("8.8.8.8")).toBeNull();
    expect(screen.getByRole("img", { name: "World map of 1 attack sources" })).toBeInTheDocument();
  });

  it("Open maps link carries hours unless 1", async () => {
    const { unmount } = compact(24);
    expect(await screen.findByRole("link", { name: "Open maps →" })).toHaveAttribute("href", "/maps?view=world&hours=24");
    unmount();
    compact(1);
    expect(await screen.findByRole("link", { name: "Open maps →" })).toHaveAttribute("href", "/maps?view=world");
  });

  it("turns setup notices into one muted line", async () => {
    h.api.mockResolvedValue(geo({ geoip_status: "no database", demo: true, home: null }));
    const { container } = compact();
    await screen.findByText("Live attack map");
    expect(container.querySelector(".notice-box")).toBeNull();
    const line = screen.getByText(/made-up demo locations/);
    expect(line.textContent).toContain("Public addresses can't be placed: no database.");
    expect(line.textContent).toContain("No protected site set");
  });

  it("no notice line when everything is configured", async () => {
    h.api.mockResolvedValue(geo({ home: { lat: 1, lon: 1, label: "Lab" } }));
    compact();
    await screen.findByText("Live attack map");
    expect(screen.queryByText(/No protected site set/)).toBeNull();
    expect(screen.queryByText(/can't be placed/)).toBeNull();
  });

  it("before data: one Live attack map card with Loading map…", async () => {
    let release!: (v: unknown) => void;
    h.api.mockReturnValue(new Promise((r) => { release = r; }));
    const { container } = compact();
    expect(screen.getByText("Live attack map")).toBeInTheDocument();
    expect(screen.getByText("Loading map…")).toBeInTheDocument();
    expect(container.querySelectorAll(".card").length).toBe(1);
    release(geo());
    await screen.findByRole("img", { name: "World map of 0 attack sources" });
    expect(screen.queryByText("Loading map…")).toBeNull();
  });

  it("first load failure shows the error inside the card, without Loading", async () => {
    h.api.mockRejectedValue(new Error("geo down"));
    const { container } = compact();
    const err = await screen.findByText("geo down");
    expect(err.closest(".card")).toHaveTextContent("Live attack map");
    expect(screen.queryByText("Loading map…")).toBeNull();
    expect(container.querySelectorAll(".card").length).toBe(1);
  });

  it("a later failed reload keeps the map and shows the error", async () => {
    compact();
    await screen.findByRole("img", { name: "World map of 0 attack sources" });
    h.api.mockRejectedValue(new Error("later boom"));
    act(() => { h.reload!(); });
    expect(await screen.findByText("later boom")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Live attack map")).toBeInTheDocument());
    expect(screen.getByRole("img", { name: "World map of 0 attack sources" })).toBeInTheDocument();
  });
});
