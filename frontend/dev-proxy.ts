import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin, ProxyOptions } from "vite";

// Validate the browser origin BEFORE mapping it to the trusted local backend origin.
// Never remove arbitrary origins or allow a public website to use this proxy.
export function localRequestAllowed(
  host: string | undefined,
  origin: string | undefined,
  site: string | undefined,
): boolean {
  return (
    !!host &&
    /^(127\.0\.0\.1|localhost):(5173|4173)$/.test(host) &&
    (!origin || origin === `http://${host}`) &&
    site !== "cross-site"
  );
}
export function localApiGuard(): Plugin {
  const guard = (
    req: IncomingMessage,
    res: ServerResponse,
    next: () => void,
  ) => {
    if (
      req.url?.startsWith("/api") &&
      !localRequestAllowed(
        req.headers.host,
        req.headers.origin,
        req.headers["sec-fetch-site"] as string | undefined,
      )
    ) {
      res.statusCode = 403;
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          error: {
            code: "local_origin_required",
            message: "Use the local AgentGuard frontend origin.",
          },
        }),
      );
      return;
    }
    next();
  };
  return {
    name: "agentguard-local-api-guard",
    configureServer(server) {
      server.middlewares.use(guard);
    },
    configurePreviewServer(server) {
      server.middlewares.use(guard);
    },
  };
}
export function backendProxy(target: string): ProxyOptions {
  const url = new URL(target);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  )
    throw new Error(
      "Backend proxy must be a loopback HTTP origin without credentials.",
    );
  return {
    target: url.origin,
    changeOrigin: true,
    configure(proxy) {
      proxy.on("proxyReq", (outgoing, incoming) => {
        if (incoming.headers.origin) outgoing.setHeader("Origin", url.origin);
        outgoing.removeHeader("forwarded");
        outgoing.removeHeader("x-forwarded-for");
        outgoing.removeHeader("x-forwarded-host");
      });
    },
  };
}
