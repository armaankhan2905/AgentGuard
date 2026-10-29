import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { backendProxy, localRequestAllowed } from "../../dev-proxy";

describe("local API proxy boundary", () => {
  it.each(["127.0.0.1:5173", "localhost:5173", "127.0.0.1:4173"])(
    "accepts only its own origin: %s",
    (host) => {
      expect(localRequestAllowed(host, `http://${host}`, "same-origin")).toBe(
        true,
      );
      expect(localRequestAllowed(host, undefined, undefined)).toBe(true);
      expect(
        localRequestAllowed(host, "https://attacker.invalid", "cross-site"),
      ).toBe(false);
      expect(localRequestAllowed(host, undefined, "cross-site")).toBe(false);
    },
  );
  it.each([
    "attacker.invalid:5173",
    "127.0.0.1.evil:5173",
    "127.0.0.1:8000",
    undefined,
  ])("rejects untrusted host %s", (host) => {
    expect(localRequestAllowed(host, undefined, undefined)).toBe(false);
  });
  it.each([
    "https://example.com",
    "http://user:secret@127.0.0.1:8000",
    "http://127.0.0.1:8000/path",
    "http://127.0.0.1:8000?secret=value",
  ])("rejects unsafe backend target", (target) =>
    expect(() => backendProxy(target)).toThrow(),
  );
  it("accepts the loopback backend origin", () =>
    expect(backendProxy("http://127.0.0.1:8000").target).toBe(
      "http://127.0.0.1:8000",
    ));
  it("closes the browser response when the backend aborts a stream", () => {
    const handlers: Record<string, (...args: never[]) => void> = {};
    const proxy = { on: (name: string, fn: (...args: never[]) => void) => (handlers[name] = fn) };
    backendProxy("http://127.0.0.1:8000").configure?.(proxy as never, {});
    for (const complete of [false, true]) {
      const upstream = new EventEmitter() as EventEmitter & { complete: boolean };
      upstream.complete = complete;
      const response = { writableEnded: false, destroy: vi.fn() };
      (handlers.proxyRes as (u: unknown, i: unknown, r: unknown) => void)(upstream, {}, response);
      upstream.emit("close");
      expect(response.destroy).toHaveBeenCalledTimes(complete ? 0 : 1);
    }
  });
});
