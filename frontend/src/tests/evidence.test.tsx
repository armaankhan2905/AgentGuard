import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Highlighted } from "../pages/Scanner";
import {
  decisionGraph,
  requestPathGraph,
  topology,
  traceGraph,
} from "../graph/model";
import { shouldPoll } from "../pages/Simulations";
import type { FirewallEvent, Indicator, Trace } from "../api/types";

describe("evidence fidelity", () => {
  it("keeps authorization before tools and scanning after document/database results", () => {
    const { edges } = topology();
    const ids = edges.map((e) => e.id);
    expect(ids).toContain("gateway-firewall");
    expect(ids).toContain("firewall-document");
    expect(ids).toContain("document-scanner");
    expect(ids).toContain("database-scanner");
    expect(ids).not.toContain("email-scanner");
    expect(edges.every((e) => !e.animated)).toBe(true);
  });
  it("does not interpret ALLOW as execution or DENY as confidential access", () => {
    for (const decision of ["ALLOW", "DENY"] as const) {
      const graph = decisionGraph({
        decision,
        tool_name: "read_document",
        reason: "Test policy",
      } as FirewallEvent);
      expect(graph.edges.find((e) => e.id === "firewall-document")?.label).toBe(
        decision === "DENY" ? "DENY · not executed" : "ALLOW · authorization",
      );
      expect(
        graph.edges.find((e) => e.id === "document-resources")?.label,
      ).toBeUndefined();
    }
  });
  it("counts actual trace events and omits controls from the baseline sandbox", () => {
    const graph = traceGraph(
      [
        { event_type: "MODEL_REQUEST", details: {} },
        { event_type: "TOOL_REQUEST", details: {} },
      ] as Trace[],
      true,
    );
    expect(
      graph.nodes.some((n) => n.id === "firewall" || n.id === "scanner"),
    ).toBe(false);
    expect(graph.nodes.find((n) => n.id === "agent")?.data.state).toBe(
      "1 recorded",
    );
    expect(graph.nodes.find((n) => n.id === "document")?.data.state).toBe(
      "No event in page",
    );
    expect(
      graph.nodes.find((n) => n.id === "document")?.data.description,
    ).toContain("confidential fixtures");
  });
  it("limits the chat mini graph to the selected tool path", () => {
    const graph = requestPathGraph(undefined, "read_document");
    expect(graph.nodes.map((n) => n.id).sort()).toEqual([
      "agent",
      "document",
      "firewall",
      "gateway",
    ]);
    expect(
      graph.edges.every(
        (e) =>
          graph.nodes.some((n) => n.id === e.source) &&
          graph.nodes.some((n) => n.id === e.target),
      ),
    ).toBe(true);
  });
  it("uses Python codepoint offsets and never renders markup as HTML", () => {
    const { container } = render(
      <Highlighted
        text={"😀<script>bad</script>"}
        indicators={[{ view: "original", start: 1, end: 9 }] as Indicator[]}
      />,
    );
    expect(container.querySelector("mark")).toHaveTextContent("<script>");
    expect(container.querySelector("script")).toBeNull();
  });
  it("does not map normalized or invalid offsets onto original text", () => {
    const { container } = render(
      <Highlighted
        text="hello"
        indicators={
          [
            { view: "view_decoded", start: 0, end: 5 },
            { view: "original", start: -1, end: 2 },
            { view: "original", start: 1, end: 100 },
          ] as Indicator[]
        }
      />,
    );
    expect(container.querySelector("mark")).toBeNull();
    expect(container).toHaveTextContent("hello");
  });
  it.each(["COMPLETED", "CANCELLED", "PARTIAL", "ERROR", "INTERRUPTED"])(
    "stops polling at %s",
    (status) => expect(shouldPoll(status, 0, 10)).toBe(false),
  );
  it("bounds active polling to four minutes", () => {
    expect(shouldPoll("RUNNING", 0, 239999)).toBe(true);
    expect(shouldPoll("RUNNING", 0, 240000)).toBe(false);
    expect(shouldPoll("QUEUED", 0, 1)).toBe(true);
  });
});
