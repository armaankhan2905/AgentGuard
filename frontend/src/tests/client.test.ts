import { describe, expect, it, vi } from "vitest";
import { api, queryString, request } from "../api/client";

describe("API transport", () => {
  it("submits exactly one comparison and captures its real admission ID", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ run_id: "run-1", status: "QUEUED" }), {
          status: 202,
        }),
      );
    vi.stubGlobal("fetch", fetch);
    expect(
      await api.launch("instruction_override", "live", "compare"),
    ).toMatchObject({ run_id: "run-1" });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][0]).toBe("/api/simulation/compare");
    expect(fetch.mock.calls[0][1]).toMatchObject({
      method: "POST",
      credentials: "omit",
      body: JSON.stringify({
        scenario_id: "instruction_override",
        mode: "live",
        compare: true,
      }),
    });
    expect(fetch.mock.calls[0][1].headers).not.toHaveProperty("Authorization");
  });
  it.each([
    ["simulation_live_disabled", 503],
    ["rate_limit_exceeded", 429],
    ["ai_unavailable", 502],
  ])("preserves %s without retrying", async (code, status) => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code,
              message: "Safe explanation",
              session_id: "session-1",
            },
          }),
          { status },
        ),
      );
    vi.stubGlobal("fetch", fetch);
    await expect(api.chat("hello")).rejects.toMatchObject({
      code,
      status,
      sessionId: "session-1",
      message: "Safe explanation",
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("does not relay an unreadable upstream error body", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html>private upstream details</html>", {
            status: 500,
          }),
        ),
    );
    await expect(request("/health")).rejects.toMatchObject({
      code: "http_error",
      message: "Request failed (500).",
    });
  });
  it("reports network failure without invented data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("internal transport details")),
    );
    await expect(api.health()).rejects.toMatchObject({
      code: "network_error",
      status: 0,
    });
  });
  it("bounds waiting and warns that submitted work may still be running", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url, options: RequestInit) =>
          new Promise((_resolve, reject) =>
            options.signal?.addEventListener("abort", () =>
              reject(new DOMException("aborted", "AbortError")),
            ),
          ),
      ),
    );
    const pending = expect(
      request("/agent/chat", { body: { message: "hello" }, timeout: 10 }),
    ).rejects.toMatchObject({
      code: "timeout",
      message: expect.stringContaining("may still be running"),
    });
    await vi.advanceTimersByTimeAsync(10);
    await pending;
  });
  it("propagates query cancellation instead of showing a network failure", async () => {
    const controller = new AbortController();
    controller.abort();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new DOMException("aborted", "AbortError")),
    );
    await expect(api.health(controller.signal)).rejects.toMatchObject({
      name: "AbortError",
    });
  });
  it("encodes supported filters and omits blank values", () => {
    expect(
      queryString({
        tool: "read_document",
        session_id: "",
        offset: 0,
        search: undefined,
      }),
    ).toBe("?tool=read_document&offset=0");
  });
});
