import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { decisionTone } from "../components/ui";
import { SimulationResult } from "../components/SimulationResult";
import { SimulationStats } from "../components/SimulationStats";
import type { Result, SimulationStats as Stats } from "../api/types";

vi.mock("../graph/NeuralCanvas", () => ({
  NeuralCanvas: () => <div>Graph</div>,
}));
const variant = {
  results: 2,
  attack_successes: 2,
  conclusive_attacks: 2,
  attack_success_rate: 1,
  false_positive_rate: null,
  legitimate_task_completion_rate: 0,
  blocked_actions: 3,
  unauthorized_tool_attempts: 2,
  injections_detected: 4,
  critical_content_quarantined: 5,
  legitimate_tasks_completed: 6,
  errors: 0,
  inconclusive: 0,
  provider_errors: 0,
};
vi.mock("../api/hooks", () => ({
  useSimStats: () => ({
    isPending: false,
    isError: false,
    data: {
      total_simulations: 2,
      interpretation: "",
      modes: {
        scripted: {
          total_runs: 2,
          variants: { baseline: variant, protected: variant },
        },
        live: { total_runs: 0, variants: {} },
      },
    } as unknown as Stats,
  }),
}));

describe("stage 6 verification regressions", () => {
  it.each(["rejected", "failed"])(
    "shows a firewall-%s tool execution as a threat, not neutral",
    (status) => expect(decisionTone(status)).toBe("danger"),
  );
  it.each([
    ["scripted", "Scripted model turns"],
    ["live", "Provider requests"],
  ] as const)(
    "labels %s model requests without implying a real provider",
    (mode, label) => {
      render(
        <SimulationResult
          variant="protected"
          traces={[]}
          loaded={false}
          result={
            {
              outcome: "SUCCESS",
              mode,
              provider_requests: 3,
            } as Result
          }
        />,
      );
      expect(screen.getByText(label)).toBeVisible();
    },
  );
  it("surfaces denials, detections, quarantines and legitimate completions", () => {
    render(<SimulationStats />);
    expect(
      screen.getAllByText(
        /3 firewall denials · 4 injection detections · 5 critical quarantines · 6\s+legitimate tasks completed/,
      ),
    ).toHaveLength(2);
  });
});
