import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes, Link } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "motion/react";
import { Toaster } from "sonner";
import { Shell } from "./components/Shell";
import { InspectorProvider } from "./components/Inspector";
import { Loading } from "./components/ui";
const Overview = lazy(() => import("./pages/Overview"));
const Agent = lazy(() => import("./pages/Agent"));
const Firewall = lazy(() => import("./pages/Firewall"));
const Scanner = lazy(() => import("./pages/Scanner"));
const Simulations = lazy(() => import("./pages/Simulations"));
const Audit = lazy(() => import("./pages/Audit"));
const System = lazy(() => import("./pages/System"));
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 20000, retry: false, refetchOnWindowFocus: false },
    mutations: { retry: false },
  },
});
export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <MotionConfig reducedMotion="user">
        <BrowserRouter>
          <InspectorProvider>
            <Suspense fallback={<Loading />}>
              <Routes>
                <Route element={<Shell />}>
                  <Route index element={<Overview />} />
                  <Route path="agent" element={<Agent />} />
                  <Route path="firewall" element={<Firewall />} />
                  <Route path="scanner" element={<Scanner />} />
                  <Route path="simulations" element={<Simulations />} />
                  <Route path="audit" element={<Audit />} />
                  <Route path="system" element={<System />} />
                  <Route
                    path="*"
                    element={
                      <div className="empty">
                        <h1>Page not found</h1>
                        <Link to="/">Return to Neural Overview</Link>
                      </div>
                    }
                  />
                </Route>
              </Routes>
            </Suspense>
          </InspectorProvider>
          <Toaster
            theme="dark"
            richColors
            closeButton
            position="bottom-right"
          />
        </BrowserRouter>
      </MotionConfig>
    </QueryClientProvider>
  );
}
