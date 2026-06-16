import { afterEach, describe, expect, it, vi } from "vitest";
import { requestWake } from "./wake";

const CONTROLLER = "https://ctl.example.com";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("requestWake", () => {
  it("POSTs to the controller's /wake and resolves on 202", async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 202 })));
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestWake(CONTROLLER)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(`${CONTROLLER}/wake`, { method: "POST" });
  });

  it("resolves on 200 (already running)", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(null, { status: 200 }))));
    await expect(requestWake(CONTROLLER)).resolves.toBeUndefined();
  });

  it("throws on a non-2xx controller error", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(null, { status: 500 }))));
    await expect(requestWake(CONTROLLER)).rejects.toThrow(/HTTP 500/);
  });
});
