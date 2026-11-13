import { render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import App from "../App";

const auth = vi.hoisted(() => ({ role: "analyst" }));
vi.mock("../auth", () => ({
  useAuth: () => ({ me: { username: "ann", role: auth.role }, loading: false, logout: vi.fn() }),
}));
vi.mock("../live", () => ({ useLiveStatus: () => false, useLiveAlerts: () => false }));
vi.mock("../pages/ThreatCenter", () => ({ default: () => <div>threat-center-stub</div> }));
vi.mock("../pages/Maps", () => ({ default: () => {
  const l = useLocation();
  if (l.search.includes("view=world") && (globalThis as { __boom?: boolean }).__boom) throw new Error("map crashed");
  return <div>maps-stub {l.search}</div>;
} }));
vi.mock("../pages/Response", () => ({ default: () => <div>response-stub</div> }));
vi.mock("../pages/Alerts", () => ({ default: () => <div>alerts-stub</div> }));
vi.mock("../pages/AlertDetail", () => ({ default: () => <div>detail-stub</div> }));
vi.mock("../pages/Cases", () => ({ default: () => <div>cases-stub</div> }));
vi.mock("../pages/Assistant", () => ({ default: () => <div>assistant-stub</div> }));
vi.mock("../pages/Admin", () => ({ default: () => <div>admin-stub</div> }));
vi.mock("../pages/Login", () => ({ default: () => <div>login-stub</div> }));

function Loc() { const l = useLocation(); return <div data-testid="loc">{l.pathname + l.search}</div>; }
function Nav() { const n = useNavigate(); return <button onClick={() => n("/maps")}>nav-maps</button>; }
beforeEach(() => { auth.role = "analyst"; });
const go = (url: string) => render(<MemoryRouter initialEntries={[url]}><App /><Loc /><Nav /></MemoryRouter>);

describe("legacy route redirects", () => {
  it.each([
    ["/blocks", "response-stub", "/response"],
    ["/actions", "response-stub", "/response"],
    ["/map", "maps-stub ?view=world", "/maps?view=world"],
    ["/topology", "maps-stub", "/maps"],
    ["/metrics", "threat-center-stub", "/"],
  ])("%s -> %s", async (from, text, loc) => {
    go(from);
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(screen.getByTestId("loc").textContent).toBe(loc);
  });

  it.each(["/cases", "/cases/5"])("%s renders the Cases page", async (url) => {
    go(url);
    expect(await screen.findByText("cases-stub")).toBeInTheDocument();
    expect(screen.getByTestId("loc").textContent).toBe(url);
  });

  it("hides the admin route from analysts", () => {
    go("/admin");
    expect(screen.getByText("Page not found.")).toBeInTheDocument();
  });

  it("keeps the query string on redirects", async () => {
    go("/blocks?ip=10.0.0.1");
    expect(await screen.findByText("response-stub")).toBeInTheDocument();
    expect(screen.getByTestId("loc").textContent).toBe("/response?ip=10.0.0.1");
  });

  it("/map?hours=6 goes to /maps with hours and view=world", async () => {
    go("/map?hours=6");
    await screen.findByText(/maps-stub/);
    const [path, qs] = screen.getByTestId("loc").textContent!.split("?");
    expect(path).toBe("/maps");
    const p = new URLSearchParams(qs);
    expect(p.get("hours")).toBe("6");
    expect(p.get("view")).toBe("world");
  });

  it("an admin can open /admin", () => {
    auth.role = "admin";
    go("/admin");
    expect(screen.getByText("admin-stub")).toBeInTheDocument();
  });

  it("the error boundary resets when only the query changes", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    (globalThis as { __boom?: boolean }).__boom = true;
    try {
      go("/maps?view=world");
      expect(await screen.findByText("This page couldn't be shown")).toBeInTheDocument();
      screen.getByText("nav-maps").click();
      expect(await screen.findByText(/maps-stub/)).toBeInTheDocument();
    } finally {
      delete (globalThis as { __boom?: boolean }).__boom;
      err.mockRestore();
    }
  });
});
