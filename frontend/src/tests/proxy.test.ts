import { describe, expect, it } from "vitest";
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
});
