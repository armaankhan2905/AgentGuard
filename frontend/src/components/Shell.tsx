import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Network,
  Bot,
  ShieldCheck,
  ScanLine,
  FlaskConical,
  ScrollText,
  Activity,
  PanelLeftClose,
  PanelLeftOpen,
  RotateCw,
  ArrowUpRight,
} from "lucide-react";
import { useSystem } from "../api/hooks";
import { Badge } from "./ui";
const navigation = [
  ["/", "Neural Overview", Network],
  ["/agent", "AI Agent", Bot],
  ["/firewall", "Security Firewall", ShieldCheck],
  ["/scanner", "Injection Scanner", ScanLine],
  ["/simulations", "Attack Simulation", FlaskConical],
  ["/audit", "Audit Explorer", ScrollText],
  ["/system", "System Status", Activity],
] as const;
export function Shell() {
  const [expanded, setExpanded] = useState(true);
  const location = useLocation();
  const query = useQueryClient();
  const status = useSystem();
  const current =
    navigation.find((n) => n[0] === location.pathname)?.[1] || "Workspace";
  return (
    <div className={`app-shell ${expanded ? "expanded" : "collapsed"}`}>
      <a className="skip-link" href="#main">
        Skip to workspace
      </a>
      <aside className="nav-rail">
        <NavLink to="/" className="brand" aria-label="AgentGuard home">
          <img src="/shield.svg" alt="" />
          <span>
            AGENT<span className="cyan">GUARD</span>
            <small>NEURAL SHIELD</small>
          </span>
        </NavLink>
        <div className="nav-section">
          WORKSPACE <span>01—07</span>
        </div>
        <nav aria-label="Main navigation">
          {navigation.map(([path, label, Icon], i) => (
            <NavLink key={path} to={path} end={path === "/"} title={label}>
              <Icon size={19} />
              <span>{label}</span>
              <small>0{i + 1}</small>
            </NavLink>
          ))}
        </nav>
        <div className="nav-bottom">
          <div className="local-note">
            <span className="status-dot" />
            <span>
              LOCAL WORKSPACE<small>Controlled demonstration</small>
            </span>
          </div>
          <button
            className="collapse-button"
            onClick={() => setExpanded(!expanded)}
            aria-label={expanded ? "Collapse navigation" : "Expand navigation"}
          >
            {expanded ? (
              <PanelLeftClose size={18} />
            ) : (
              <PanelLeftOpen size={18} />
            )}
            <span>Collapse sidebar</span>
          </button>
        </div>
      </aside>
      <div className="workspace">
        <header className="command-bar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{current}</strong>
          </div>
          <div className="connection-group">
            <Badge
              tone={
                status.isError
                  ? "danger"
                  : status.data?.backend.available
                    ? "success"
                    : "neutral"
              }
            >
              {status.isError
                ? "Backend offline"
                : status.data
                  ? "Backend connected"
                  : "Connecting"}
            </Badge>
            <span className="provider-label">
              AI{" "}
              {status.isError
                ? "unavailable"
                : status.data?.ai_provider.configured
                  ? "configured · unverified"
                  : "not configured"}
            </span>
            <button
              aria-label="Refresh backend data"
              onClick={() => query.invalidateQueries()}
            >
              <RotateCw size={16} />
            </button>
            <a
              className="docs-link"
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
              aria-label="Open backend API documentation"
            >
              <ArrowUpRight size={16} />
            </a>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          <Outlet />
        </main>
        <footer className="workspace-footer">
          <span>
            AGENTGUARD <span className="cyan">/</span> NEURAL SHIELD
          </span>
          <span>Local development · Historical records, not a live stream</span>
          <span>
            {status.data && !status.isError
              ? `v${status.data.version}`
              : "API unavailable"}
          </span>
        </footer>
      </div>
    </div>
  );
}
