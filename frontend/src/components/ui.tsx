import { AlertCircle, ArrowLeft, ArrowRight, RotateCw } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "../api/client";

export const date = (value: string) =>
  new Date(
    /[Zz]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`,
  ).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
export const human = (value: string) =>
  value.replaceAll("_", " ").toLowerCase();
export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return (
    <span className={`badge ${tone}`}>
      <span className="status-dot" />
      {children}
    </span>
  );
}
export function decisionTone(value: string) {
  return ["ALLOW", "SAFE", "COMPLETED", "succeeded"].includes(value)
    ? "success"
    : [
          "DENY",
          "BLOCK",
          "CRITICAL",
          "ERROR",
          "quarantined",
          "rejected",
          "failed",
        ].includes(value)
      ? "danger"
      : [
            "FLAG",
            "REDACT",
            "HIGH",
            "MEDIUM",
            "RUNNING",
            "QUEUED",
            "PARTIAL",
          ].includes(value)
        ? "warning"
        : "neutral";
}
export function PageTitle({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-title">
      <div>
        <div className="eyebrow">
          <span />
          {eyebrow}
        </div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
export function Panel({
  title,
  kicker,
  children,
  className = "",
  actions,
}: {
  title?: string;
  kicker?: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <div className="panel-header">
          <div>
            {kicker && <span className="eyebrow">{kicker}</span>}
            <h2>{title}</h2>
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}
export function Notice({ children }: { children: ReactNode }) {
  return (
    <div className="notice">
      <AlertCircle size={16} />
      <div>{children}</div>
    </div>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty" role="status">
      <span className="empty-orbit" />
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status" aria-label="Loading data">
      <span />
      <span />
      <span />
    </div>
  );
}
export function ErrorState({
  error,
  retry,
}: {
  error: unknown;
  retry?: () => void;
}) {
  const e = error instanceof Error ? error.message : "Unable to load data.";
  const hint =
    error instanceof ApiError
      ? error.status === 404
        ? "This feature is not available. Enable the local backend development routes."
        : error.status === 403
          ? "Access denied. Use the guarded local frontend proxy."
          : error.status === 429
            ? "The backend rate limit was reached. Wait before submitting again."
            : error.status === 409
              ? "Another operation is active. Open its history and wait for completion."
              : ""
      : "";
  return (
    <div className="error-state" role="alert">
      <AlertCircle size={18} />
      <div>
        <strong>{e}</strong>
        {hint && <p>{hint}</p>}
        {retry && (
          <button className="text-button" onClick={retry}>
            <RotateCw size={14} />
            Retry read
          </button>
        )}
      </div>
    </div>
  );
}
export function Metric({
  label,
  value,
  note,
  tone = "neutral",
}: {
  label: string;
  value: number | string | undefined;
  note?: string;
  tone?: string;
}) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>
        {value === undefined
          ? "—"
          : typeof value === "number"
            ? value.toLocaleString()
            : value}
      </strong>
      <small>{value === undefined ? "Unavailable" : note}</small>
    </div>
  );
}
export function Pager({
  offset,
  size,
  count,
  onChange,
}: {
  offset: number;
  size: number;
  count: number;
  onChange: (offset: number) => void;
}) {
  return (
    <div className="pager">
      <span>
        Page {Math.floor(offset / size) + 1} · {count} records
      </span>
      <div>
        <button
          aria-label="Previous page"
          disabled={!offset}
          onClick={() => onChange(Math.max(0, offset - size))}
        >
          <ArrowLeft size={16} />
        </button>
        <button
          aria-label="Next page"
          disabled={count < size}
          onClick={() => onChange(offset + size)}
        >
          <ArrowRight size={16} />
        </button>
      </div>
    </div>
  );
}
export function JsonDetails({ value }: { value: unknown }) {
  return (
    <details className="json-details">
      <summary>Inspect recorded metadata</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}
