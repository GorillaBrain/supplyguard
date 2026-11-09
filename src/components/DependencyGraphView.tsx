"use client";

import React, { useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  AlertTriangle,
  Box,
  CheckCircle2,
  Filter,
  GitBranch,
  Layers,
  Search,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import {
  DependencyNode,
  ScanReport,
  Severity,
  SuspiciousPackageFinding,
  VulnerabilityFinding,
} from "@/types/security";

interface DependencyGraphViewProps {
  report: ScanReport;
}

export function DependencyGraphView({ report }: DependencyGraphViewProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [highlightVulnerablePaths, setHighlightVulnerablePaths] =
    useState<boolean>(true);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Map package node ID -> vulnerabilities & suspicious findings
  const nodeVulnsMap = useMemo(() => {
    const map = new Map<string, VulnerabilityFinding[]>();
    for (const dep of report.dependencies) {
      const matching = report.vulnerabilities.filter(
        (v) =>
          v.ecosystem === dep.ecosystem &&
          v.packageName.toLowerCase() === dep.name.toLowerCase() &&
          v.installedVersion === dep.version
      );
      if (matching.length > 0) {
        map.set(dep.id, matching);
      }
    }
    return map;
  }, [report.dependencies, report.vulnerabilities]);

  const nodeSuspMap = useMemo(() => {
    const map = new Map<string, SuspiciousPackageFinding>();
    for (const dep of report.dependencies) {
      const match = report.suspiciousPackages.find(
        (s) =>
          s.ecosystem === dep.ecosystem &&
          s.packageName.toLowerCase() === dep.name.toLowerCase()
      );
      if (match) {
        map.set(dep.id, match);
      }
    }
    return map;
  }, [report.dependencies, report.suspiciousPackages]);

  const filteredDependencies = useMemo(() => {
    return report.dependencies.filter((dep) => {
      const matchesSearch =
        !searchQuery.trim() ||
        dep.name.toLowerCase().includes(searchQuery.trim().toLowerCase()) ||
        dep.version.toLowerCase().includes(searchQuery.trim().toLowerCase());

      if (!matchesSearch) return false;
      if (severityFilter === "ALL") return true;

      const vulns = nodeVulnsMap.get(dep.id) ?? [];
      const susp = nodeSuspMap.get(dep.id);
      if (severityFilter === "VULNERABLE_OR_SUSPICIOUS") {
        return vulns.length > 0 || Boolean(susp);
      }
      if (severityFilter === "CLEAN") {
        return vulns.length === 0 && !susp;
      }
      return (
        vulns.some((v) => v.severity === (severityFilter as Severity)) ||
        susp?.severity === (severityFilter as Severity)
      );
    });
  }, [
    report.dependencies,
    searchQuery,
    severityFilter,
    nodeVulnsMap,
    nodeSuspMap,
  ]);

  const { nodes, edges } = useMemo(() => {
    const visibleIds = new Set<string>(["root"]);
    filteredDependencies.forEach((d) => visibleIds.add(d.id));

    // Also include parent direct nodes if a transitive node matches filter so path from root is connected
    for (const dep of filteredDependencies) {
      for (const pId of dep.parents) {
        if (pId !== "root") visibleIds.add(pId);
      }
    }

    const activeDeps = report.dependencies.filter((d) => visibleIds.has(d.id));
    const directDeps = activeDeps.filter((d) => d.scope === "direct");
    const transitiveDeps = activeDeps.filter((d) => d.scope === "transitive");

    const builtNodes: Node[] = [];

    // Root Node
    const rootY = Math.max(180, (directDeps.length * 88) / 2);
    builtNodes.push({
      id: "root",
      position: { x: 40, y: rootY },
      data: {
        label: (
          <div className="text-left">
            <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400">
              ROOT PROJECT
            </div>
            <div className="text-xs font-semibold text-zinc-100 truncate max-w-[175px]">
              {report.projectName.split(" ")[0]}
            </div>
            <div className="text-[10px] font-mono text-zinc-400 mt-0.5">
              {report.dependencies.length} total packages
            </div>
          </div>
        ),
      },
      style: {
        background: "#11151E",
        border: "1.5px solid #10B981",
        borderRadius: "8px",
        padding: "8px 10px",
        width: 205,
        color: "#F4F4F5",
      },
    });

    const createPackageNode = (
      dep: DependencyNode,
      x: number,
      y: number
    ): Node => {
      const vulns = nodeVulnsMap.get(dep.id) ?? [];
      const susp = nodeSuspMap.get(dep.id);
      const hasCritical = vulns.some((v) => v.severity === "CRITICAL") || susp?.severity === "CRITICAL";
      const hasHigh = vulns.some((v) => v.severity === "HIGH") || susp?.severity === "HIGH";
      const hasIssue = vulns.length > 0 || Boolean(susp);

      let borderColor = "#27272A";
      let badgeBg = "bg-zinc-800 text-zinc-300";
      let statusLabel = "CLEAN";

      if (hasCritical) {
        borderColor = "#EF4444";
        badgeBg = "bg-rose-950/90 text-rose-300 border border-rose-700/60";
        statusLabel = "CRITICAL";
      } else if (hasHigh) {
        borderColor = "#F97316";
        badgeBg = "bg-orange-950/90 text-orange-300 border border-orange-700/60";
        statusLabel = "HIGH RISK";
      } else if (hasIssue) {
        borderColor = "#EAB308";
        badgeBg = "bg-amber-950/90 text-amber-300 border border-amber-700/60";
        statusLabel = susp ? "SUSPICIOUS" : "VULN";
      }

      const isSelected = selectedNodeId === dep.id;

      return {
        id: dep.id,
        position: { x, y },
        data: {
          label: (
            <div className="text-left">
              <div className="flex items-center justify-between gap-1.5 mb-1">
                <span className="text-[10px] font-mono text-zinc-400 uppercase">
                  {dep.ecosystem} · {dep.scope}
                </span>
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.2 rounded ${badgeBg}`}
                >
                  {statusLabel}
                </span>
              </div>
              <div className="text-xs font-semibold text-zinc-100 truncate max-w-[190px]">
                {dep.name}
              </div>
              <div className="flex items-center justify-between mt-1 text-[10px] font-mono text-zinc-400">
                <span>v{dep.version}</span>
                <span>{dep.license ?? "N/A"}</span>
              </div>
            </div>
          ),
        },
        style: {
          background: isSelected ? "#182030" : "#0E1015",
          border: `${isSelected ? "2px" : "1.5px"} solid ${
            isSelected ? "#34D399" : borderColor
          }`,
          borderRadius: "8px",
          padding: "7px 9px",
          width: 225,
          cursor: "pointer",
        },
      };
    };

    directDeps.forEach((dep, idx) => {
      builtNodes.push(createPackageNode(dep, 340, 30 + idx * 88));
    });

    transitiveDeps.forEach((dep, idx) => {
      builtNodes.push(createPackageNode(dep, 660, 45 + idx * 92));
    });

    // Build Edges
    const builtEdges: Edge[] = [];
    for (const edge of report.edges) {
      if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) continue;

      const targetVulns = nodeVulnsMap.get(edge.target) ?? [];
      const targetSusp = nodeSuspMap.get(edge.target);
      const isRiskyEdge = targetVulns.length > 0 || Boolean(targetSusp);

      builtEdges.push({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: highlightVulnerablePaths && isRiskyEdge,
        style: {
          stroke:
            highlightVulnerablePaths && isRiskyEdge
              ? "#F43F5E"
              : edge.scope === "direct"
              ? "#3F3F46"
              : "#27272A",
          strokeWidth: highlightVulnerablePaths && isRiskyEdge ? 2 : 1.25,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color:
            highlightVulnerablePaths && isRiskyEdge ? "#F43F5E" : "#52525B",
        },
      });
    }

    return { nodes: builtNodes, edges: builtEdges };
  }, [
    filteredDependencies,
    report.dependencies,
    report.edges,
    report.projectName,
    nodeVulnsMap,
    nodeSuspMap,
    highlightVulnerablePaths,
    selectedNodeId,
  ]);

  const selectedDep = useMemo(() => {
    if (!selectedNodeId || selectedNodeId === "root") return null;
    return report.dependencies.find((d) => d.id === selectedNodeId) ?? null;
  }, [selectedNodeId, report.dependencies]);

  const selectedVulns = selectedDep
    ? nodeVulnsMap.get(selectedDep.id) ?? []
    : [];
  const selectedSusp = selectedDep ? nodeSuspMap.get(selectedDep.id) : undefined;

  return (
    <div className="space-y-4">
      {/* Graph Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search package or version..."
              className="bg-[#090A0D] border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/70 w-56"
            />
          </div>

          <div className="flex items-center gap-1.5 bg-[#090A0D] border border-zinc-800 rounded-md px-2.5 py-1.5">
            <Filter className="w-3.5 h-3.5 text-zinc-500" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-xs text-zinc-300 focus:outline-none"
            >
              <option value="ALL" className="bg-[#0E1015]">
                All Packages ({report.dependencies.length})
              </option>
              <option value="VULNERABLE_OR_SUSPICIOUS" className="bg-[#0E1015]">
                Vulnerable or Suspicious Only
              </option>
              <option value="CRITICAL" className="bg-[#0E1015]">
                Critical Severity
              </option>
              <option value="HIGH" className="bg-[#0E1015]">
                High Severity
              </option>
              <option value="MEDIUM" className="bg-[#0E1015]">
                Medium Severity
              </option>
              <option value="CLEAN" className="bg-[#0E1015]">
                Clean Packages Only
              </option>
            </select>
          </div>

          <button
            type="button"
            onClick={() =>
              setHighlightVulnerablePaths(!highlightVulnerablePaths)
            }
            className={`px-2.5 py-1.5 rounded-md text-xs font-medium border transition flex items-center gap-1.5 ${
              highlightVulnerablePaths
                ? "bg-rose-950/50 border-rose-700/70 text-rose-300"
                : "bg-[#090A0D] border-zinc-800 text-zinc-400 hover:text-zinc-200"
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            Highlight Vulnerable Paths
          </button>
        </div>

        <div className="flex items-center gap-4 text-[11px] font-mono text-zinc-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
            Root
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
            Critical/High
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
            Medium/Suspicious
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-zinc-600 inline-block" />
            Clean
          </span>
        </div>
      </div>

      {/* Main Graph + Node Inspector Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 h-[520px] bg-[#090A0D] border border-zinc-800/80 rounded-lg overflow-hidden relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodeClick={(_, node) => setSelectedNodeId(node.id)}
            fitView
            minZoom={0.25}
            maxZoom={1.75}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1F2430" gap={20} size={1} />
            <Controls className="!bg-[#13161D] !border-zinc-800 !fill-zinc-300" />
            <MiniMap
              nodeColor={(n) => {
                if (n.id === "root") return "#10B981";
                if (nodeVulnsMap.has(n.id) || nodeSuspMap.has(n.id))
                  return "#EF4444";
                return "#3F3F46";
              }}
              maskColor="rgba(9, 10, 13, 0.75)"
              className="!bg-[#0E1015] !border !border-zinc-800"
            />
          </ReactFlow>
        </div>

        {/* Node Inspector Panel */}
        <div className="lg:col-span-4 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 flex flex-col justify-between h-[520px] overflow-y-auto">
          {selectedDep ? (
            <div className="space-y-4">
              <div className="border-b border-zinc-800 pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono uppercase text-emerald-400">
                    {selectedDep.ecosystem} · {selectedDep.scope} dependency
                  </span>
                  <span className="text-xs font-mono text-zinc-400">
                    Depth {selectedDep.depth}
                  </span>
                </div>
                <h3 className="text-base font-semibold text-zinc-100 mt-1 font-mono break-all">
                  {selectedDep.name}@{selectedDep.version}
                </h3>
                <p className="text-xs text-zinc-400 mt-1">
                  Source Manifest:{" "}
                  <span className="font-mono text-zinc-300">
                    {selectedDep.sourceFile}
                  </span>
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="bg-[#090A0D] border border-zinc-800/80 rounded p-2.5">
                  <div className="text-zinc-500 text-[11px]">SPDX License</div>
                  <div className="font-mono text-zinc-200 mt-0.5">
                    {selectedDep.license ?? "UNKNOWN"}
                  </div>
                </div>
                <div className="bg-[#090A0D] border border-zinc-800/80 rounded p-2.5">
                  <div className="text-zinc-500 text-[11px]">Install Hooks</div>
                  <div className="font-mono text-zinc-200 mt-0.5">
                    {selectedDep.hasInstallScripts ? "Present" : "None"}
                  </div>
                </div>
              </div>

              {/* Vulnerabilities on Selected Node */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  Advisories ({selectedVulns.length})
                </h4>
                {selectedVulns.length === 0 ? (
                  <div className="text-xs text-zinc-500 bg-[#090A0D] border border-zinc-800/60 rounded p-2.5 flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    No known CVEs/GHSAs matched for this version.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {selectedVulns.map((v) => (
                      <div
                        key={v.id}
                        className="bg-rose-950/20 border border-rose-900/50 rounded p-2.5 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="text-rose-300 font-semibold">
                            {v.cveId ?? v.id}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                            {v.severity}{" "}
                            {v.cvssScore !== null ? `(${v.cvssScore})` : ""}
                          </span>
                        </div>
                        <p className="text-zinc-300 text-[11px] leading-relaxed">
                          {v.title}
                        </p>
                        <div className="text-[11px] font-mono text-emerald-400 pt-1">
                          Fix: {v.fixedVersion ?? "No upstream patch"}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Suspicious Package Indicators on Selected Node */}
              {selectedSusp && (
                <div className="bg-amber-950/20 border border-amber-800/60 rounded p-3 space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-amber-300 flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Suspicion Score: {selectedSusp.suspicionScore}/100
                    </span>
                  </div>
                  <ul className="text-[11px] text-zinc-300 space-y-1 list-disc pl-4">
                    {selectedSusp.indicators.map((ind, i) => (
                      <li key={i}>{ind.description}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Dependency Relationships */}
              <div className="space-y-2 pt-1">
                <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                  <GitBranch className="w-3.5 h-3.5 text-zinc-400" />
                  Dependency Lineage
                </div>
                <div className="text-xs bg-[#090A0D] border border-zinc-800/80 rounded p-2.5 font-mono text-zinc-300">
                  <div>
                    Parents:{" "}
                    <span className="text-zinc-400">
                      {selectedDep.parents.join(", ") || "root"}
                    </span>
                  </div>
                  <div className="mt-1">
                    Children:{" "}
                    <span className="text-zinc-400">
                      {selectedDep.children.length > 0
                        ? selectedDep.children
                            .map((c) => c.split(":")[1] ?? c)
                            .join(", ")
                        : "Leaf package (0 transitive children)"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center px-4 text-zinc-400 space-y-2">
              <Layers className="w-8 h-8 text-zinc-600 stroke-1" />
              <div className="text-sm font-medium text-zinc-200">
                Interactive Dependency Node Inspector
              </div>
              <p className="text-xs text-zinc-500 leading-relaxed">
                Click any node in the dependency graph to inspect its resolved
                version, lineage path, CVE/GHSA advisories, lifecycle script
                telemetry, and SPDX license classification.
              </p>
            </div>
          )}

          <div className="border-t border-zinc-800/80 pt-3 mt-4 flex items-center justify-between text-[11px] text-zinc-500 font-mono">
            <span>Showing {filteredDependencies.length} nodes</span>
            <span>{report.edges.length} graph edges</span>
          </div>
        </div>
      </div>

      {/* Complete Dependency Inventory Table */}
      <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Box className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Resolved Dependency Inventory ({filteredDependencies.length})
            </h3>
          </div>
          <span className="text-[11px] font-mono text-zinc-400">
            Click any row to focus node in graph
          </span>
        </div>
        <div className="overflow-x-auto max-h-80">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-zinc-800/80 text-[11px] font-mono uppercase text-zinc-400 bg-[#090A0D]">
                <th className="py-2.5 px-4">Package</th>
                <th className="py-2.5 px-3">Version</th>
                <th className="py-2.5 px-3">Ecosystem</th>
                <th className="py-2.5 px-3">Scope</th>
                <th className="py-2.5 px-3">License</th>
                <th className="py-2.5 px-3">Security Status</th>
                <th className="py-2.5 px-4">Source File</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {filteredDependencies.map((dep) => {
                const vulns = nodeVulnsMap.get(dep.id) ?? [];
                const susp = nodeSuspMap.get(dep.id);
                return (
                  <tr
                    key={dep.id}
                    onClick={() => setSelectedNodeId(dep.id)}
                    className={`cursor-pointer transition ${
                      selectedNodeId === dep.id
                        ? "bg-emerald-950/20"
                        : "hover:bg-zinc-900/60"
                    }`}
                  >
                    <td className="py-2.5 px-4 font-mono font-medium text-zinc-100">
                      {dep.name}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-zinc-300">
                      {dep.version}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-zinc-400">
                      {dep.ecosystem}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                          dep.scope === "direct"
                            ? "bg-zinc-800 text-zinc-200"
                            : "bg-zinc-900 text-zinc-400 border border-zinc-800"
                        }`}
                      >
                        {dep.scope}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-zinc-300">
                      {dep.license ?? "UNKNOWN"}
                    </td>
                    <td className="py-2.5 px-3">
                      {vulns.length > 0 || susp ? (
                        <div className="flex flex-wrap gap-1">
                          {vulns.length > 0 && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/70">
                              {vulns.length} Vuln(s)
                            </span>
                          )}
                          {susp && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/70">
                              Suspicion {susp.suspicionScore}/100
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/50">
                          Verified Clean
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-zinc-400">
                      {dep.sourceFile}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
