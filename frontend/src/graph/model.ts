import type { Edge, Node } from "@xyflow/react";
import type { FirewallEvent, Trace } from "../api/types";
export type NeuralData = {
  label: string;
  subtitle: string;
  kind: string;
  state: string;
  description: string;
  [key: string]: unknown;
};
export type NeuralNode = Node<NeuralData, "neural">;
const nodes: [string, string, string, string, number, number, string][] = [
  [
    "user",
    "User request",
    "Conversation input",
    "user",
    0,
    240,
    "User messages enter the agent conversation.",
  ],
  [
    "agent",
    "AI agent",
    "Model-directed requests",
    "agent",
    210,
    240,
    "The model selects structured tool calls. Provider identity is not exposed by the status endpoint.",
  ],
  [
    "gateway",
    "Tool gateway",
    "One execution boundary",
    "gateway",
    420,
    240,
    "Every normal-agent tool request passes through ToolGateway.",
  ],
  [
    "firewall",
    "Security firewall",
    "Stage 3 · before execution",
    "firewall",
    630,
    240,
    "Default-deny authorization and a committed audit precede tool effects.",
  ],
  [
    "document",
    "Document tool",
    "Approved public documents",
    "document",
    850,
    80,
    "Exact approved document identities; no unrestricted file access.",
  ],
  [
    "database",
    "Database tool",
    "Synthetic records only",
    "database",
    850,
    260,
    "Bounded, approved-category searches. No arbitrary SQL or writes.",
  ],
  [
    "email",
    "Email tool",
    "Simulated delivery only",
    "email",
    850,
    440,
    "Authorized email requests create database records; no email is delivered.",
  ],
  [
    "scanner",
    "Injection scanner",
    "Stage 4 · returned content",
    "scanner",
    630,
    -25,
    "Scans document and database results after authorized reads, before returning content to model context. Email receipts are not scanned.",
  ],
  [
    "resources",
    "Protected resources",
    "Public / confidential boundary",
    "resource",
    1070,
    260,
    "Public fixtures, synthetic records and a simulated outbox. Confidential resources remain restricted by Stage 3.",
  ],
];
export function topology(baseline = false): {
  nodes: NeuralNode[];
  edges: Edge[];
} {
  const n = nodes
    .filter((x) => !baseline || !["firewall", "scanner"].includes(x[0]))
    .map(([id, label, subtitle, kind, x, y, description]) => ({
      id,
      type: "neural" as const,
      position: { x, y },
      data: { label, subtitle, kind, state: "Topology", description },
    }));
  const pairs = baseline
    ? [
        ["user", "agent"],
        ["agent", "gateway"],
        ["gateway", "document"],
        ["gateway", "database"],
        ["gateway", "email"],
        ["document", "resources"],
        ["database", "resources"],
        ["email", "resources"],
      ]
    : [
        ["user", "agent"],
        ["agent", "gateway"],
        ["gateway", "firewall"],
        ["firewall", "document"],
        ["firewall", "database"],
        ["firewall", "email"],
        ["document", "resources"],
        ["database", "resources"],
        ["email", "resources"],
        ["document", "scanner"],
        ["database", "scanner"],
        ["scanner", "agent"],
      ];
  return {
    nodes: n,
    edges: pairs.map(([source, target]) => ({
      id: `${source}-${target}`,
      source,
      target,
      type: "smoothstep",
      label:
        target === "scanner"
          ? "returned content"
          : source === "scanner"
            ? "handled result"
            : undefined,
      style: { stroke: "#395064", strokeWidth: 1.4 },
      labelStyle: { fill: "#95a8bd", fontSize: 11 },
      labelBgStyle: { fill: "#0b1321" },
      markerEnd: { type: "arrowclosed" as const, color: "#395064" },
      data: {
        description:
          "Architecture relationship; not evidence of a recorded execution.",
      },
    })),
  };
}
export const toolNode = (name: string) =>
  ({
    read_document: "document",
    search_database: "database",
    send_email: "email",
  })[name];
export function requestPathGraph(event?: FirewallEvent, tool?: string) {
  const graph = decisionGraph(event);
  const target = tool ? toolNode(tool) : undefined;
  const positions: Record<string, { x: number; y: number }> = {
    agent: { x: 0, y: 0 },
    gateway: { x: 210, y: 0 },
    firewall: { x: 210, y: 155 },
    ...(target ? { [target]: { x: 0, y: 155 } } : {}),
  };
  return {
    nodes: graph.nodes
      .filter((n) => n.id in positions)
      .map((n) => ({ ...n, position: positions[n.id] })),
    edges: graph.edges.filter(
      (e) => e.source in positions && e.target in positions,
    ),
  };
}
export function decisionGraph(event?: FirewallEvent, baseline = false) {
  const graph = topology(baseline);
  if (!event) return graph;
  const target = toolNode(event.tool_name);
  graph.nodes = graph.nodes.map((n) =>
    n.id === "firewall"
      ? { ...n, data: { ...n.data, state: event.decision } }
      : n,
  );
  graph.edges = graph.edges.map((e) =>
    e.source === "firewall" && e.target === target
      ? {
          ...e,
          label:
            event.decision === "DENY"
              ? "DENY · not executed"
              : "ALLOW · authorization",
          style: {
            stroke: event.decision === "DENY" ? "#ef6c79" : "#35d399",
            strokeWidth: 2.5,
          },
          data: { description: event.reason, event },
        }
      : e,
  );
  return graph;
}
export function traceGraph(traces: Trace[], baseline: boolean) {
  const graph = topology(baseline);
  const counts: Record<string, number> = {};
  for (const trace of traces) {
    const id =
      trace.event_type === "MODEL_REQUEST"
        ? "agent"
        : trace.event_type === "TOOL_REQUEST"
          ? "gateway"
          : trace.event_type === "FIREWALL_EVALUATION"
            ? "firewall"
            : trace.event_type === "INJECTION_SCAN"
              ? "scanner"
              : trace.event_type === "TOOL_EXECUTION"
                ? toolNode(String(trace.details.tool_name))
                : undefined;
    if (id) counts[id] = (counts[id] || 0) + 1;
  }
  const descriptions: Record<string, string> = {
    agent:
      "The simulation provider generates structured requests. Scripted mode uses deterministic responses; live mode calls the configured LLM.",
    gateway:
      "The isolated simulation dispatcher validates tool schemas and confines all effects to synthetic sandbox resources.",
    document: baseline
      ? "The baseline can read scenario-owned public and confidential fixtures inside the sandbox."
      : "Document access is authorized by Stage 3 inside the isolated sandbox.",
    email:
      "Writes only to the simulation outbox. Nothing is sent to an external email service.",
    resources:
      "Scenario-owned fixtures, synthetic records and an isolated outbox. Objective outcome and actual confidential access are reported separately.",
  };
  graph.nodes = graph.nodes.map((n) => ({
    ...n,
    data: {
      ...n.data,
      ...(descriptions[n.id] ? { description: descriptions[n.id] } : {}),
      ...(n.id === "document" && baseline
        ? { subtitle: "Synthetic scenario documents" }
        : {}),
      state: counts[n.id] ? `${counts[n.id]} recorded` : "No event in page",
    },
  }));
  const latest = [...traces]
    .reverse()
    .find((t) => t.event_type === "FIREWALL_EVALUATION");
  if (latest) {
    const target = toolNode(String(latest.details.tool_name));
    graph.edges = graph.edges.map((e) =>
      e.source === "firewall" && e.target === target
        ? {
            ...e,
            label: String(latest.details.decision),
            style: {
              stroke:
                latest.details.decision === "DENY" ? "#ef6c79" : "#35d399",
              strokeWidth: 2.5,
            },
            data: {
              description: "Latest matching decision in the loaded trace page.",
              trace: latest,
            },
          }
        : e,
    );
  }
  return graph;
}
