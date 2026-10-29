import { memo, useCallback, useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useReactFlow,
  type NodeProps,
  type Edge,
} from "@xyflow/react";
import {
  Bot,
  ShieldCheck,
  ScanLine,
  FileText,
  Database,
  Mail,
  LockKeyhole,
  UserRound,
  GitBranch,
  Focus,
  RotateCcw,
} from "lucide-react";
import { useReducedMotion } from "motion/react";
import { animateEdges, type NeuralNode } from "./model";
import { useInspector } from "../components/Inspector";
const icons = {
  agent: Bot,
  firewall: ShieldCheck,
  scanner: ScanLine,
  document: FileText,
  database: Database,
  email: Mail,
  resource: LockKeyhole,
  user: UserRound,
  gateway: GitBranch,
};
const NeuralNodeView = memo(function NeuralNodeView({
  data,
  selected,
}: NodeProps<NeuralNode>) {
  const Icon = icons[data.kind as keyof typeof icons] || GitBranch;
  return (
    <div
      className={`neural-node node-${data.kind} ${selected ? "is-selected" : ""} ${typeof data.tone === "string" ? `live-${data.tone}` : ""}`}
      title={data.description}
      role="button"
      tabIndex={0}
      aria-label={`Inspect ${data.label}`}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          event.currentTarget.click();
        }
      }}
    >
      <Handle type="target" position={Position.Left} />
      {typeof data.pulse === "string" && (
        // Re-keyed per event so the CSS pulse replays once; disabled by reduced motion.
        <span className="node-pulse" key={data.pulse} aria-hidden="true" />
      )}
      <div className="node-top">
        <span className="node-icon">
          <Icon size={22} />
        </span>
        <span
          className={`node-state ${data.state === "DENY" ? "danger" : data.state === "ALLOW" ? "success" : typeof data.tone === "string" ? data.tone : ""}`}
        >
          {data.state}
        </span>
      </div>
      <strong>{data.label}</strong>
      <small>{data.subtitle}</small>
      <Handle type="source" position={Position.Right} />
    </div>
  );
});
const nodeTypes = { neural: NeuralNodeView };
function Canvas({
  graph,
  compact = false,
  label,
}: {
  graph: { nodes: NeuralNode[]; edges: Edge[] };
  compact?: boolean;
  label: string;
}) {
  const [nodes, setNodes, onNodesChange] = useNodesState(graph.nodes);
  const [selected, setSelected] = useState<string>();
  const { fitView } = useReactFlow();
  const inspect = useInspector();
  const reduced = useReducedMotion();
  useEffect(() => setNodes(graph.nodes), [graph.nodes, setNodes]);
  const edges = useMemo(
    () =>
      animateEdges(graph.edges, selected, !!reduced),
    [graph.edges, reduced, selected],
  );
  const select = useCallback(
    (node: NeuralNode) => {
      setSelected(node.id);
      inspect({
        title: node.data.label,
        kind: "Network node",
        description: node.data.description,
        data: node.data,
      });
    },
    [inspect],
  );
  return (
    <div
      className={`neural-canvas ${compact ? "compact" : ""}`}
      aria-label={label}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onNodeClick={(_, node) => select(node)}
        onPaneClick={() => setSelected(undefined)}
        onEdgeClick={(_, edge) =>
          inspect({
            title: `${edge.source} → ${edge.target}`,
            kind: "Network connection",
            description:
              typeof edge.data?.description === "string"
                ? edge.data.description
                : undefined,
            data: edge.data,
          })
        }
        fitView
        fitViewOptions={{ padding: 0.12 }}
        minZoom={0.25}
        maxZoom={1.5}
        nodesConnectable={false}
        edgesReconnectable={false}
        deleteKeyCode={null}
      >
        <Background color="#243149" gap={22} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
      <div className="graph-actions">
        <button
          aria-label="Focus selected node"
          disabled={!selected}
          onClick={() =>
            fitView({
              nodes: [{ id: selected! }],
              duration: reduced ? 0 : 350,
              maxZoom: 1.2,
            })
          }
        >
          <Focus size={15} />
        </button>
        <button
          aria-label="Reset graph layout"
          onClick={() => {
            setNodes(graph.nodes);
            setSelected(undefined);
            requestAnimationFrame(() =>
              fitView({ duration: reduced ? 0 : 350 }),
            );
          }}
        >
          <RotateCcw size={15} />
        </button>
      </div>
      <div className="graph-caption">{label}</div>
    </div>
  );
}
export function NeuralCanvas(props: {
  graph: { nodes: NeuralNode[]; edges: Edge[] };
  compact?: boolean;
  label: string;
}) {
  return (
    <ReactFlowProvider>
      <Canvas {...props} />
    </ReactFlowProvider>
  );
}
