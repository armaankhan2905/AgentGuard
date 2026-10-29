import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Simulations from "../pages/Simulations";
import { api, ApiError } from "../api/client";
import type { RunDetail, Scenario } from "../api/types";

vi.mock("../graph/NeuralCanvas", () => ({
  NeuralCanvas: () => <div>Graph</div>,
}));
vi.mock("../components/SimulationStats", () => ({
  SimulationStats: () => <div>Statistics</div>,
}));
vi.mock("../api/client", async (original) => ({
  ...(await original<typeof import("../api/client")>()),
  api: {
    scenarios: vi.fn(),
    runs: vi.fn(),
    run: vi.fn(),
    traces: vi.fn(),
    launch: vi.fn(),
    cancel: vi.fn(),
  },
}));
const scenario: Scenario = {
  id: "instruction_override",
  name: "Instruction override",
  description: "Synthetic test",
  category: "instruction_override",
  difficulty: "intermediate",
  objective: "Generate a forbidden request",
  entry_point: "document",
  expected_controls: [],
  success_criteria: "Request observed",
  benign: false,
  version: 1,
  supported_modes: ["scripted", "live"],
};
const run: RunDetail = {
  run_id: "test-run",
  scenario_id: scenario.id,
  mode: "scripted",
  status: "RUNNING",
  is_simulation: true,
  created_at: "2026-10-29T00:00:00Z",
  started_at: null,
  completed_at: null,
  error_code: null,
  configuration: {
    scenario,
    label: "Scripted",
    model: null,
    provider: "scripted",
    variants: ["baseline", "protected"],
  },
  results: {},
  comparison: { paired: true },
  trace_summary: {},
  cancel_requested: false,
};
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
      <Simulations />
    </QueryClientProvider>,
  );
beforeEach(() => {
  vi.mocked(api.scenarios).mockResolvedValue([scenario]);
  vi.mocked(api.runs).mockResolvedValue([]);
  vi.mocked(api.traces).mockResolvedValue([]);
});
describe("simulation lifecycle", () => {
  it("captures admission, polls until completed, and does not launch again", async () => {
    vi.mocked(api.launch).mockResolvedValue({
      run_id: run.run_id,
      status: "QUEUED",
      mode: "scripted",
      is_simulation: true,
    });
    vi.mocked(api.run)
      .mockResolvedValueOnce(run)
      .mockResolvedValue({
        ...run,
        status: "COMPLETED",
        results: {
          protected: {
            outcome: "SUCCESS",
            attack_success: true,
            execution_status: "COMPLETED",
            error_code: null,
            mode: "scripted",
            is_simulation: true,
            confidential_data_accessed: false,
            blocked_actions: 1,
          },
        },
      });
    setup();
    const button = await screen.findByRole("button", {
      name: "Launch simulation",
    });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    expect(await screen.findByText("test-run")).toBeVisible();
    expect(await screen.findByText("RUNNING")).toBeVisible();
    expect(
      await screen.findByText("COMPLETED", {}, { timeout: 4000 }),
    ).toBeVisible();
    expect(screen.getByText("Confidential access")).toBeVisible();
    expect(screen.getByText("No", { exact: true })).toBeVisible();
    await new Promise((resolve) => setTimeout(resolve, 2200));
    expect(api.run).toHaveBeenCalledTimes(2);
    expect(api.launch).toHaveBeenCalledTimes(1);
  }, 10000);
  it("does not fabricate a run after rejected admission", async () => {
    vi.mocked(api.launch).mockRejectedValue(
      new ApiError(
        503,
        "simulation_live_disabled",
        "Live simulation is disabled.",
      ),
    );
    setup();
    const button = await screen.findByRole("button", {
      name: "Launch simulation",
    });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    expect(
      await screen.findByText("Live simulation is disabled."),
    ).toBeVisible();
    expect(api.run).not.toHaveBeenCalled();
    expect(screen.queryByText("SELECTED RUN")).not.toBeInTheDocument();
  });
});
