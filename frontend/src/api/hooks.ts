import { useQuery } from "@tanstack/react-query";
import { api } from "./client";
export const useSystem = () =>
  useQuery({
    queryKey: ["system"],
    queryFn: ({ signal }) => api.status(signal),
    refetchInterval: 30000,
  });
export const useFirewallStats = () =>
  useQuery({
    queryKey: ["firewall-stats"],
    queryFn: ({ signal }) => api.firewallStats(signal),
  });
export const useScanStats = () =>
  useQuery({
    queryKey: ["scan-stats"],
    queryFn: ({ signal }) => api.scanStats(signal),
  });
export const useSimStats = () =>
  useQuery({
    queryKey: ["simulation-stats"],
    queryFn: ({ signal }) => api.simulationStats(signal),
  });
export const usePolicies = () =>
  useQuery({
    queryKey: ["policies"],
    queryFn: ({ signal }) => api.policies(signal),
  });
