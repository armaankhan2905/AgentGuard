import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Firewall from "../pages/Firewall";
import { api, ApiError } from "../api/client";

vi.mock("../graph/NeuralCanvas", () => ({
  NeuralCanvas: () => <div>Graph</div>,
}));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: { policies: vi.fn(), evaluate: vi.fn() },
}));
const setup = () =>
  render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: {
            queries: { retry: false },
            mutations: { retry: false },
          },
        })
      }
    >
      <Firewall />
    </QueryClientProvider>,
  );
beforeEach(() => {
  vi.mocked(api.policies).mockResolvedValue({
    valid: true,
    default_decision: "DENY",
    deny_overrides_allow: true,
    baseline_guards: [],
    rules: [],
  });
});
describe("firewall workbench", () => {
  it("rejects non-object JSON before calling the backend", async () => {
    setup();
    fireEvent.change(screen.getByLabelText("Arguments"), {
      target: { value: "[]" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Evaluate request" }));
    expect(
      await screen.findByText("Arguments must be a valid JSON object."),
    ).toBeVisible();
    expect(api.evaluate).not.toHaveBeenCalled();
  });
  it("submits confidential evaluation and shows the returned denial reason", async () => {
    vi.mocked(api.evaluate).mockResolvedValue({
      decision: "DENY",
      decision_id: "decision-test",
      session_id: "session-test",
      tool_name: "read_document",
      risk_level: "HIGH",
      reason: "Confidential access is denied.",
      policy_id: "deny-confidential",
      timestamp: "2026-10-29T00:00:00Z",
      arguments_summary: {
        validated: true,
        document_id: "confidential_strategy.txt",
      },
      metadata: {},
    });
    setup();
    fireEvent.click(
      screen.getByRole("button", { name: "Try a confidential document" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Evaluate request" }));
    await waitFor(() =>
      expect(screen.getByText("Confidential access is denied.")).toBeVisible(),
    );
    expect(
      screen.getByText(
        'validated: true · document_id: "confidential_strategy.txt"',
      ),
    ).toBeVisible();
    expect(api.evaluate).toHaveBeenCalledExactlyOnceWith("read_document", {
      filename: "confidential_strategy.txt",
    });
  });
  it("shows API failures instead of an invented decision", async () => {
    vi.mocked(api.evaluate).mockRejectedValue(
      new ApiError(503, "service_unavailable", "Backend unavailable."),
    );
    setup();
    fireEvent.click(screen.getByRole("button", { name: "Evaluate request" }));
    expect(await screen.findByText("Backend unavailable.")).toBeVisible();
    expect(screen.queryByText("ALLOW")).not.toBeInTheDocument();
  });
});
