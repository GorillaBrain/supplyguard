"use client";

import React, { useMemo, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Code2,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  FileCode,
  FileJson,
  FileSpreadsheet,
  FileText,
  FolderGit2,
  GitBranch,
  Globe,
  KeyRound,
  LayoutDashboard,
  Lock,
  Menu,
  Package,
  Play,
  Plus,
  RefreshCw,
  Scale,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  Trash2,
  Upload,
  Workflow,
  X,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  RiskScoringWeights,
  ScanReport,
  Severity,
  VulnerabilityFinding,
} from "@/types/security";
import {
  DEFAULT_RISK_WEIGHTS,
  calculateProjectRiskScore,
} from "@/lib/scanners/risk-score";
import { LICENSE_LEGAL_DISCLAIMER } from "@/lib/scanners/licenses";
import {
  downloadPdfSecurityReport,
  generateCycloneDxSbom,
  generateStructuredReportJson,
} from "@/lib/reports/exporter";
import { SAMPLE_FIXTURE_PRESETS } from "@/lib/demo-fixtures";
import { DependencyGraphView } from "@/components/DependencyGraphView";

export type NavSection =
  | "overview"
  | "projects"
  | "scan"
  | "vulnerabilities"
  | "dependencies"
  | "supply-chain"
  | "cicd"
  | "secrets"
  | "licenses"
  | "reports"
  | "settings";

interface SupplyGuardAppProps {
  initialReports: ScanReport[];
}

const SEVERITY_BADGE_STYLES: Record<Severity, string> = {
  CRITICAL: "bg-rose-950/90 text-rose-300 border border-rose-700/70",
  HIGH: "bg-orange-950/90 text-orange-300 border border-orange-700/70",
  MEDIUM: "bg-amber-950/90 text-amber-300 border border-amber-700/70",
  LOW: "bg-sky-950/80 text-sky-300 border border-sky-800/70",
  INFO: "bg-zinc-800/90 text-zinc-300 border border-zinc-700",
};

export function SupplyGuardApp({ initialReports }: SupplyGuardAppProps) {
  const [reports, setReports] = useState<ScanReport[]>(initialReports);
  const [activeReportId, setActiveReportId] = useState<string>(
    initialReports[0]?.id ?? ""
  );
  const [activeNav, setActiveNav] = useState<NavSection>("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  // Configurable Risk Scoring Weights
  const [riskWeights, setRiskWeights] =
    useState<RiskScoringWeights>(DEFAULT_RISK_WEIGHTS);
  const [customInternalPrefixes, setCustomInternalPrefixes] = useState<string>(
    "@corp/, @internal/, internal-, finops-"
  );

  // Scan Repository State
  const [scanTab, setScanTab] = useState<"github" | "upload" | "sbom">(
    "github"
  );
  const [repoUrlInput, setRepoUrlInput] = useState<string>("");
  const [projectNameInput, setProjectNameInput] = useState<string>("");
  const [uploadedFiles, setUploadedFiles] = useState<
    { name: string; content: string }[]
  >([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [activeScanStages, setActiveScanStages] = useState<string[]>([]);

  // Vulnerability Explorer State
  const [vulnSearch, setVulnSearch] = useState<string>("");
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState<string>("ALL");
  const [vulnScopeFilter, setVulnScopeFilter] = useState<string>("ALL");
  const [selectedVuln, setSelectedVuln] =
    useState<VulnerabilityFinding | null>(null);

  // License Explorer State
  const [licenseCategoryFilter, setLicenseCategoryFilter] =
    useState<string>("ALL");

  // Copy feedback
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const baseActiveReport = useMemo(() => {
    return (
      reports.find((r) => r.id === activeReportId) ?? reports[0]
    );
  }, [reports, activeReportId]);

  // Dynamically recompute RiskScore when user adjusts weights in Settings
  const activeReport: ScanReport = useMemo(() => {
    if (!baseActiveReport) return initialReports[0];
    const recomputedRisk = calculateProjectRiskScore({
      dependencies: baseActiveReport.dependencies,
      vulnerabilities: baseActiveReport.vulnerabilities,
      suspiciousPackages: baseActiveReport.suspiciousPackages,
      dependencyConfusion: baseActiveReport.dependencyConfusion,
      cicdFindings: baseActiveReport.cicdFindings,
      secretFindings: baseActiveReport.secretFindings,
      licenseFindings: baseActiveReport.licenseFindings,
      weights: riskWeights,
    });
    return {
      ...baseActiveReport,
      riskScore: recomputedRisk,
    };
  }, [baseActiveReport, riskWeights, initialReports]);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 1800);
  };

  // File Upload Handler
  const handleFileInputChange = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    setScanError(null);
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    const loaded: { name: string; content: string }[] = [];
    for (let i = 0; i < fileList.length; i++) {
      const f = fileList[i];
      if (f.size > 5 * 1024 * 1024) {
        setScanError(
          `File '${f.name}' exceeds the 5 MB per-file security limit.`
        );
        return;
      }
      const text = await f.text();
      loaded.push({ name: f.name, content: text });
    }
    setUploadedFiles((prev) => [...prev, ...loaded]);
  };

  const handleLoadFixtureIntoUploader = (presetId: string) => {
    const preset = SAMPLE_FIXTURE_PRESETS.find((p) => p.id === presetId);
    if (!preset) return;
    setScanTab("upload");
    setProjectNameInput(preset.name.replace(" (Sample Benchmark)", ""));
    setUploadedFiles(preset.files);
    setScanError(null);
  };

  // Execute Real Server-Side Scan
  const handleRunScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanError(null);
    setIsScanning(true);
    setActiveScanStages([
      "Validating input & enforcing SSRF / file-size policy...",
      "Resolving manifests, lockfiles & dependency graph edges...",
      "Querying OSV.dev & advisory vulnerability intelligence...",
      "Executing typosquatting, homograph & lifecycle script heuristics...",
      "Running static CI/CD workflow & entropy secret scanners...",
    ]);

    try {
      const prefixes = customInternalPrefixes
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      const payload =
        scanTab === "github"
          ? {
              mode: "github" as const,
              repositoryUrl: repoUrlInput.trim(),
              projectName: projectNameInput.trim() || undefined,
              internalPrefixes: prefixes,
            }
          : {
              mode: "upload" as const,
              projectName:
                projectNameInput.trim() ||
                uploadedFiles[0]?.name ||
                "Uploaded Project Scan",
              files: uploadedFiles,
              internalPrefixes: prefixes,
            };

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok || !data.ok || !data.report) {
        throw new Error(data.error ?? "Scan failed to complete.");
      }

      const newReport: ScanReport = data.report;
      setReports((prev) => [newReport, ...prev]);
      setActiveReportId(newReport.id);
      setActiveNav("overview");
    } catch (err) {
      setScanError(
        err instanceof Error ? err.message : "Failed to execute security scan."
      );
    } finally {
      setIsScanning(false);
    }
  };

  // Filtered Vulnerabilities
  const filteredVulnerabilities = useMemo(() => {
    return activeReport.vulnerabilities.filter((v) => {
      if (vulnSeverityFilter !== "ALL" && v.severity !== vulnSeverityFilter) {
        return false;
      }
      if (
        vulnScopeFilter !== "ALL" &&
        v.dependencyScope !== vulnScopeFilter
      ) {
        return false;
      }
      if (vulnSearch.trim()) {
        const q = vulnSearch.trim().toLowerCase();
        return (
          v.packageName.toLowerCase().includes(q) ||
          (v.cveId ?? "").toLowerCase().includes(q) ||
          (v.ghsaId ?? "").toLowerCase().includes(q) ||
          v.title.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [
    activeReport.vulnerabilities,
    vulnSeverityFilter,
    vulnScopeFilter,
    vulnSearch,
  ]);

  // Analytics Data for Recharts
  const severityChartData = useMemo(() => {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    activeReport.vulnerabilities.forEach((v) => counts[v.severity]++);
    activeReport.suspiciousPackages.forEach((s) => counts[s.severity]++);
    activeReport.cicdFindings.forEach((c) => counts[c.severity]++);
    activeReport.secretFindings.forEach((sec) => counts[sec.severity]++);

    return [
      { name: "Critical", value: counts.CRITICAL, color: "#F43F5E" },
      { name: "High", value: counts.HIGH, color: "#F97316" },
      { name: "Medium", value: counts.MEDIUM, color: "#EAB308" },
      { name: "Low", value: counts.LOW, color: "#38BDF8" },
    ];
  }, [activeReport]);

  const categoryChartData = useMemo(() => {
    return activeReport.riskScore.categoryScores.map((c) => ({
      name: c.category.split(" ")[0],
      fullName: c.category,
      score: c.normalizedScore,
      weighted: c.weightedContribution,
    }));
  }, [activeReport.riskScore.categoryScores]);

  const licenseSummaryCounts = useMemo(() => {
    const map: Record<string, number> = {
      PERMISSIVE: 0,
      WEAK_COPYLEFT: 0,
      STRONG_COPYLEFT: 0,
      NETWORK_COPYLEFT: 0,
      UNKNOWN: 0,
    };
    activeReport.licenseFindings.forEach((l) => {
      map[l.category] = (map[l.category] ?? 0) + 1;
    });
    return map;
  }, [activeReport.licenseFindings]);

  const navItems: {
    id: NavSection;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number;
    badgeTone?: "rose" | "amber" | "zinc";
  }[] = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    {
      id: "projects",
      label: "Projects",
      icon: FolderGit2,
      badge: reports.length,
      badgeTone: "zinc",
    },
    { id: "scan", label: "Scan Repository", icon: Play },
    {
      id: "vulnerabilities",
      label: "Vulnerabilities",
      icon: ShieldAlert,
      badge: activeReport.vulnerabilities.length,
      badgeTone: activeReport.vulnerabilities.length > 0 ? "rose" : "zinc",
    },
    {
      id: "dependencies",
      label: "Dependencies",
      icon: GitBranch,
      badge: activeReport.dependencies.length,
      badgeTone: "zinc",
    },
    {
      id: "supply-chain",
      label: "Supply Chain Risks",
      icon: AlertOctagon,
      badge:
        activeReport.suspiciousPackages.length +
        activeReport.dependencyConfusion.length,
      badgeTone:
        activeReport.suspiciousPackages.length +
          activeReport.dependencyConfusion.length >
        0
          ? "amber"
          : "zinc",
    },
    {
      id: "cicd",
      label: "CI/CD Security",
      icon: Workflow,
      badge: activeReport.cicdFindings.length,
      badgeTone: activeReport.cicdFindings.length > 0 ? "rose" : "zinc",
    },
    {
      id: "secrets",
      label: "Secrets",
      icon: KeyRound,
      badge: activeReport.secretFindings.length,
      badgeTone: activeReport.secretFindings.length > 0 ? "rose" : "zinc",
    },
    {
      id: "licenses",
      label: "License Compliance",
      icon: Scale,
      badge: activeReport.licenseFindings.filter((l) => l.isRestrictive).length,
      badgeTone:
        activeReport.licenseFindings.filter((l) => l.isRestrictive).length > 0
          ? "amber"
          : "zinc",
    },
    { id: "reports", label: "Reports & SBOM", icon: FileText },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  const handleDownloadJsonReport = () => {
    const jsonStr = generateStructuredReportJson(activeReport);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `supplyguard-assessment-${activeReport.id.toLowerCase()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCycloneDx = () => {
    const sbom = generateCycloneDxSbom(activeReport);
    const blob = new Blob([JSON.stringify(sbom, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `supplyguard-sbom-${activeReport.id.toLowerCase()}.cdx.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#090A0D] text-zinc-200 flex flex-col md:flex-row">
      {/* Mobile Header */}
      <div className="md:hidden flex items-center justify-between px-4 py-3 bg-[#0E1015] border-b border-zinc-800/80">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <span className="font-semibold text-sm tracking-tight text-zinc-100">
              SupplyGuard
            </span>
            <span className="ml-2 text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">
              SCA v1.0
            </span>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="p-1.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300"
          aria-label="Toggle Navigation"
        >
          {mobileMenuOpen ? (
            <X className="w-4 h-4" />
          ) : (
            <Menu className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Persistent Sidebar */}
      <aside
        className={`${
          mobileMenuOpen ? "block" : "hidden"
        } md:flex flex-col justify-between bg-[#0E1015] border-r border-zinc-800/80 transition-all duration-200 shrink-0 ${
          sidebarCollapsed ? "md:w-16" : "md:w-64"
        }`}
      >
        <div>
          {/* Brand Header */}
          <div className="hidden md:flex items-center justify-between px-4 h-14 border-b border-zinc-800/80">
            {!sidebarCollapsed && (
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-md bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
                  <Shield className="w-4 h-4 text-emerald-400" />
                </div>
                <div>
                  <div className="font-semibold text-sm tracking-tight text-zinc-100 leading-none">
                    SupplyGuard
                  </div>
                  <div className="text-[10px] font-mono text-zinc-500 mt-0.5">
                    SUPPLY CHAIN INTEL
                  </div>
                </div>
              </div>
            )}
            <button
              type="button"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-1.5 rounded hover:bg-zinc-800/70 text-zinc-400 hover:text-zinc-200 transition mx-auto md:mx-0"
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {sidebarCollapsed ? (
                <ChevronRight className="w-4 h-4" />
              ) : (
                <ChevronLeft className="w-4 h-4" />
              )}
            </button>
          </div>

          {/* Active Target Selector inside Sidebar */}
          {!sidebarCollapsed && (
            <div className="p-3 border-b border-zinc-800/80">
              <label className="block text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1">
                Active Target Context
              </label>
              <select
                value={activeReport.id}
                onChange={(e) => setActiveReportId(e.target.value)}
                className="w-full bg-[#090A0D] border border-zinc-800 rounded px-2.5 py-1.5 text-xs text-zinc-200 font-mono focus:outline-none focus:border-emerald-500/60"
              >
                {reports.map((r) => (
                  <option key={r.id} value={r.id} className="bg-[#0E1015]">
                    {r.isDemoData ? "[SAMPLE] " : "[LIVE] "}
                    {r.projectName.split(" ")[0]} ({r.riskScore.overallScore})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Navigation Links */}
          <nav className="p-2 space-y-0.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeNav === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setActiveNav(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition ${
                    isActive
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                      : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900/70 border border-transparent"
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <Icon
                      className={`w-4 h-4 shrink-0 ${
                        isActive ? "text-emerald-400" : "text-zinc-400"
                      }`}
                    />
                    {!sidebarCollapsed && (
                      <span className="truncate">{item.label}</span>
                    )}
                  </div>
                  {!sidebarCollapsed && item.badge !== undefined && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                        item.badgeTone === "rose"
                          ? "bg-rose-950 text-rose-300 border border-rose-800/70"
                          : item.badgeTone === "amber"
                          ? "bg-amber-950 text-amber-300 border border-amber-800/70"
                          : "bg-zinc-800/90 text-zinc-400"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer Telemetry */}
        {!sidebarCollapsed && (
          <div className="p-3 border-t border-zinc-800/80 text-[11px] text-zinc-500 space-y-1.5">
            <div className="flex items-center justify-between">
              <span>OSV.dev Engine</span>
              <span className="text-emerald-400 font-mono flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
                ONLINE
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>SSRF Policy</span>
              <span className="text-zinc-300 font-mono">ENFORCED</span>
            </div>
            <div className="text-[10px] text-zinc-600 pt-1">
              Secure every dependency. Trust every build.
            </div>
          </div>
        )}
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Context Bar */}
        <header className="bg-[#0E1015] border-b border-zinc-800/80 px-6 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold text-zinc-100 font-mono">
                  {activeReport.projectName}
                </h1>
                {activeReport.isDemoData ? (
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-950/70 text-amber-300 border border-amber-700/60">
                    Sample Benchmark Data
                  </span>
                ) : (
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700/60">
                    Live Repository Scan
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-3 text-[11px] text-zinc-400 font-mono mt-0.5">
                <span>ID: {activeReport.id}</span>
                <span>·</span>
                <span>
                  Ecosystems: {activeReport.ecosystems.join(", ") || "Config"}
                </span>
                <span>·</span>
                <span>
                  Scanned: {new Date(activeReport.scannedAt).toLocaleString()}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => setActiveNav("scan")}
              className="px-3 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold text-xs flex items-center gap-1.5 transition"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Scan Repository
            </button>
            <button
              type="button"
              onClick={() => downloadPdfSecurityReport(activeReport)}
              className="px-3 py-1.5 rounded-md bg-[#13161D] hover:bg-zinc-800 text-zinc-200 border border-zinc-700/80 text-xs font-medium flex items-center gap-1.5 transition"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              Export PDF
            </button>
          </div>
        </header>

        {/* Explicit Sample Mode Notice Banner when inspecting seeded benchmark */}
        {activeReport.isDemoData && (
          <div className="bg-amber-950/20 border-b border-amber-800/40 px-6 py-2 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2 text-amber-200/90">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              <span>
                <strong>Sample Benchmark Mode:</strong> Viewing seeded reference
                fixture{" "}
                <span className="font-mono underline">
                  {activeReport.projectName}
                </span>{" "}
                computed by SupplyGuard&apos;s analysis engines. Paste any public
                GitHub URL or upload your own lockfiles in{" "}
                <button
                  type="button"
                  onClick={() => setActiveNav("scan")}
                  className="text-emerald-400 underline font-medium"
                >
                  Scan Repository
                </button>{" "}
                to run a live scan.
              </span>
            </div>
            <div className="flex items-center gap-2">
              {reports
                .filter((r) => r.isDemoData)
                .map((demo) => (
                  <button
                    key={demo.id}
                    type="button"
                    onClick={() => setActiveReportId(demo.id)}
                    className={`text-[11px] font-mono px-2 py-0.5 rounded border transition ${
                      activeReport.id === demo.id
                        ? "bg-amber-500/20 border-amber-500/60 text-amber-200"
                        : "bg-zinc-900/70 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    {demo.projectName.split("/")[1]?.split(" ")[0] ?? demo.id}
                  </button>
                ))}
            </div>
          </div>
        )}

        {/* Main Workspace Body */}
        <main className="p-6 space-y-6 max-w-[1600px]">
          {/* ========================================================= */}
          {/* 1. OVERVIEW DASHBOARD                                     */}
          {/* ========================================================= */}
          {activeNav === "overview" && (
            <div className="space-y-6">
              {/* Top Metric Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-3.5">
                  <div className="text-[11px] font-mono uppercase text-zinc-400 flex items-center justify-between">
                    <span>Risk Score</span>
                    <Activity className="w-3.5 h-3.5 text-emerald-400" />
                  </div>
                  <div className="mt-2 flex items-baseline gap-2">
                    <span
                      className={`text-2xl font-bold font-mono ${
                        activeReport.riskScore.overallScore >= 70
                          ? "text-rose-400"
                          : activeReport.riskScore.overallScore >= 40
                          ? "text-amber-400"
                          : "text-emerald-400"
                      }`}
                    >
                      {activeReport.riskScore.overallScore}
                    </span>
                    <span className="text-xs font-mono text-zinc-500">
                      / 100 (Grade {activeReport.riskScore.postureGrade})
                    </span>
                  </div>
                  <div className="text-[11px] text-zinc-400 mt-1">
                    {activeReport.riskScore.postureLabel}
                  </div>
                </div>

                <div
                  onClick={() => setActiveNav("dependencies")}
                  className="bg-[#0E1015] border border-zinc-800/80 hover:border-zinc-700 rounded-lg p-3.5 cursor-pointer transition"
                >
                  <div className="text-[11px] font-mono uppercase text-zinc-400 flex items-center justify-between">
                    <span>Dependencies</span>
                    <Package className="w-3.5 h-3.5 text-zinc-400" />
                  </div>
                  <div className="mt-2 text-2xl font-bold font-mono text-zinc-100">
                    {activeReport.dependencies.length}
                  </div>
                  <div className="text-[11px] text-zinc-400 mt-1 font-mono">
                    {
                      activeReport.dependencies.filter(
                        (d) => d.scope === "direct"
                      ).length
                    }{" "}
                    direct ·{" "}
                    {
                      activeReport.dependencies.filter(
                        (d) => d.scope === "transitive"
                      ).length
                    }{" "}
                    transitive
                  </div>
                </div>

                <div
                  onClick={() => setActiveNav("vulnerabilities")}
                  className="bg-[#0E1015] border border-zinc-800/80 hover:border-zinc-700 rounded-lg p-3.5 cursor-pointer transition"
                >
                  <div className="text-[11px] font-mono uppercase text-zinc-400 flex items-center justify-between">
                    <span>Vulnerabilities</span>
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  </div>
                  <div className="mt-2 text-2xl font-bold font-mono text-zinc-100">
                    {activeReport.vulnerabilities.length}
                  </div>
                  <div className="text-[11px] text-rose-400 mt-1 font-mono">
                    {
                      activeReport.vulnerabilities.filter(
                        (v) =>
                          v.severity === "CRITICAL" || v.severity === "HIGH"
                      ).length
                    }{" "}
                    Critical / High
                  </div>
                </div>

                <div
                  onClick={() => setActiveNav("supply-chain")}
                  className="bg-[#0E1015] border border-zinc-800/80 hover:border-zinc-700 rounded-lg p-3.5 cursor-pointer transition"
                >
                  <div className="text-[11px] font-mono uppercase text-zinc-400 flex items-center justify-between">
                    <span>Supply Chain</span>
                    <AlertOctagon className="w-3.5 h-3.5 text-amber-400" />
                  </div>
                  <div className="mt-2 text-2xl font-bold font-mono text-zinc-100">
                    {activeReport.suspiciousPackages.length +
                      activeReport.dependencyConfusion.length}
                  </div>
                  <div className="text-[11px] text-amber-300/90 mt-1 font-mono">
                    {activeReport.suspiciousPackages.length} typosquat ·{" "}
                    {activeReport.dependencyConfusion.length} confusion
                  </div>
                </div>

                <div
                  onClick={() => setActiveNav("cicd")}
                  className="bg-[#0E1015] border border-zinc-800/80 hover:border-zinc-700 rounded-lg p-3.5 cursor-pointer transition"
                >
                  <div className="text-[11px] font-mono uppercase text-zinc-400 flex items-center justify-between">
                    <span>CI/CD Issues</span>
                    <Workflow className="w-3.5 h-3.5 text-orange-400" />
                  </div>
                  <div className="mt-2 text-2xl font-bold font-mono text-zinc-100">
                    {activeReport.cicdFindings.length}
                  </div>
                  <div className="text-[11px] text-zinc-400 mt-1 font-mono">
                    Static workflow audit
                  </div>
                </div>

                <div
                  onClick={() => setActiveNav("secrets")}
                  className="bg-[#0E1015] border border-zinc-800/80 hover:border-zinc-700 rounded-lg p-3.5 cursor-pointer transition"
                >
                  <div className="text-[11px] font-mono uppercase text-zinc-400 flex items-center justify-between">
                    <span>Exposed Secrets</span>
                    <KeyRound className="w-3.5 h-3.5 text-rose-400" />
                  </div>
                  <div className="mt-2 text-2xl font-bold font-mono text-zinc-100">
                    {activeReport.secretFindings.length}
                  </div>
                  <div className="text-[11px] text-zinc-400 mt-1 font-mono">
                    Strictly masked
                  </div>
                </div>
              </div>

              {/* Analytics Row: Risk Domain Breakdown + Severity Distribution + License Posture */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                {/* Domain Risk Bar Chart */}
                <div className="lg:col-span-5 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                        Normalized Risk Score by Security Domain
                      </h2>
                      <p className="text-[11px] text-zinc-500">
                        0–100 saturating exponential index per domain
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveNav("settings")}
                      className="text-[11px] font-mono text-emerald-400 hover:underline"
                    >
                      Configure Weights
                    </button>
                  </div>
                  <div className="h-52">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={categoryChartData}
                        layout="vertical"
                        margin={{ top: 4, right: 16, left: 10, bottom: 4 }}
                      >
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke="#1F2430"
                          horizontal={false}
                        />
                        <XAxis
                          type="number"
                          domain={[0, 100]}
                          tick={{ fill: "#71717A", fontSize: 10 }}
                        />
                        <YAxis
                          type="category"
                          dataKey="name"
                          width={90}
                          tick={{ fill: "#D4D4D8", fontSize: 11 }}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#090A0D",
                            borderColor: "#27272A",
                            fontSize: "12px",
                          }}
                        />
                        <Bar
                          dataKey="score"
                          fill="#10B981"
                          radius={[0, 4, 4, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Severity Distribution Pie/Bar + Breakdown */}
                <div className="lg:col-span-4 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4">
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                    Finding Severity Distribution
                  </h2>
                  <p className="text-[11px] text-zinc-500 mb-3">
                    Combined advisories, supply chain, CI/CD & secret findings
                  </p>
                  <div className="grid grid-cols-2 items-center gap-2 h-48">
                    <div className="h-40">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={severityChartData}
                            dataKey="value"
                            nameKey="name"
                            innerRadius={36}
                            outerRadius={60}
                            paddingAngle={3}
                          >
                            {severityChartData.map((entry, idx) => (
                              <Cell key={idx} fill={entry.color} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{
                              backgroundColor: "#090A0D",
                              borderColor: "#27272A",
                              fontSize: "12px",
                            }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="space-y-2 text-xs font-mono">
                      {severityChartData.map((item) => (
                        <div
                          key={item.name}
                          className="flex items-center justify-between bg-[#090A0D] border border-zinc-800/70 rounded px-2.5 py-1.5"
                        >
                          <span className="flex items-center gap-2 text-zinc-300">
                            <span
                              className="w-2 h-2 rounded-full"
                              style={{ backgroundColor: item.color }}
                            />
                            {item.name}
                          </span>
                          <span className="font-semibold text-zinc-100">
                            {item.value}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* License Posture & Scan Stage Telemetry */}
                <div className="lg:col-span-3 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                        License Compliance
                      </h2>
                      <Scale className="w-3.5 h-3.5 text-emerald-400" />
                    </div>
                    <div className="space-y-2 text-xs mt-3">
                      <div className="flex items-center justify-between bg-[#090A0D] border border-zinc-800/70 rounded px-3 py-2">
                        <span className="text-zinc-400">Permissive (MIT/Apache/BSD)</span>
                        <span className="font-mono text-emerald-400 font-semibold">
                          {licenseSummaryCounts.PERMISSIVE}
                        </span>
                      </div>
                      <div className="flex items-center justify-between bg-[#090A0D] border border-zinc-800/70 rounded px-3 py-2">
                        <span className="text-zinc-400">Weak Copyleft (LGPL/MPL)</span>
                        <span className="font-mono text-amber-300 font-semibold">
                          {licenseSummaryCounts.WEAK_COPYLEFT}
                        </span>
                      </div>
                      <div className="flex items-center justify-between bg-[#090A0D] border border-zinc-800/70 rounded px-3 py-2">
                        <span className="text-zinc-400">Strong/Network (GPL/AGPL)</span>
                        <span className="font-mono text-rose-400 font-semibold">
                          {licenseSummaryCounts.STRONG_COPYLEFT +
                            licenseSummaryCounts.NETWORK_COPYLEFT}
                        </span>
                      </div>
                      <div className="flex items-center justify-between bg-[#090A0D] border border-zinc-800/70 rounded px-3 py-2">
                        <span className="text-zinc-400">Unclassified / Unknown</span>
                        <span className="font-mono text-zinc-300 font-semibold">
                          {licenseSummaryCounts.UNKNOWN}
                        </span>
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveNav("licenses")}
                    className="mt-3 w-full py-1.5 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-xs text-zinc-300 font-mono transition"
                  >
                    Inspect License Matrix →
                  </button>
                </div>
              </div>

              {/* Prioritized Remediation Plan & Most Exposed Dependencies */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                <div className="lg:col-span-8 bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden">
                  <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between">
                    <div>
                      <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                        Prioritized Remediation Action Plan (
                        {activeReport.riskScore.prioritizedRemediations.length})
                      </h2>
                      <p className="text-[11px] text-zinc-500">
                        Ranked by exploitability, direct reachability, and risk
                        score reduction impact
                      </p>
                    </div>
                  </div>
                  <div className="divide-y divide-zinc-800/60 max-h-96 overflow-y-auto">
                    {activeReport.riskScore.prioritizedRemediations.length ===
                    0 ? (
                      <div className="p-6 text-center text-xs text-zinc-400 flex flex-col items-center gap-2">
                        <ShieldCheck className="w-7 h-7 text-emerald-400" />
                        <span>
                          Zero high-priority remediations required. All scanned
                          dependencies and workflows passed security checks.
                        </span>
                      </div>
                    ) : (
                      activeReport.riskScore.prioritizedRemediations.map(
                        (rem) => (
                          <div
                            key={rem.id}
                            className="p-3.5 hover:bg-zinc-900/40 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                          >
                            <div className="space-y-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/90 text-emerald-300 border border-emerald-700/60">
                                  P{rem.priority}
                                </span>
                                <span
                                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                                    SEVERITY_BADGE_STYLES[rem.severity]
                                  }`}
                                >
                                  {rem.severity}
                                </span>
                                <span className="text-xs font-semibold text-zinc-100">
                                  {rem.title}
                                </span>
                              </div>
                              <p className="text-xs text-zinc-400">
                                {rem.description}
                              </p>
                              {rem.actionCommand && (
                                <div className="flex items-center gap-2 pt-1">
                                  <code className="text-[11px] font-mono bg-[#090A0D] border border-zinc-800 px-2 py-0.5 rounded text-emerald-300">
                                    {rem.actionCommand}
                                  </code>
                                  <button
                                    type="button"
                                    onClick={() =>
                                      handleCopy(rem.actionCommand!, rem.id)
                                    }
                                    className="text-[11px] font-mono text-zinc-400 hover:text-zinc-200 flex items-center gap-1"
                                  >
                                    <Copy className="w-3 h-3" />
                                    {copiedText === rem.id ? "Copied" : "Copy"}
                                  </button>
                                </div>
                              )}
                            </div>
                            <div className="text-right font-mono shrink-0">
                              <span className="text-xs text-emerald-400 font-semibold">
                                -{rem.impactScoreReduction} pts
                              </span>
                              <div className="text-[10px] text-zinc-500">
                                Est. Risk Reduction
                              </div>
                            </div>
                          </div>
                        )
                      )
                    )}
                  </div>
                </div>

                {/* Most Exposed Packages + Pipeline Execution Stages */}
                <div className="lg:col-span-4 space-y-4">
                  <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4">
                    <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200 mb-3">
                      Most Exposed Dependencies
                    </h2>
                    {activeReport.riskScore.mostExposedDependencies.length ===
                    0 ? (
                      <div className="text-xs text-zinc-500 py-4 text-center">
                        No exposed dependencies identified.
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        {activeReport.riskScore.mostExposedDependencies.map(
                          (pkg) => (
                            <div
                              key={`${pkg.ecosystem}:${pkg.packageName}@${pkg.version}`}
                              className="bg-[#090A0D] border border-zinc-800/80 rounded p-2.5 text-xs"
                            >
                              <div className="flex items-center justify-between font-mono">
                                <span className="text-zinc-100 font-medium">
                                  {pkg.packageName}@{pkg.version}
                                </span>
                                <span className="text-rose-400 font-semibold">
                                  Exp: {pkg.exposureScore}
                                </span>
                              </div>
                              <div className="text-[11px] text-zinc-400 mt-1 font-mono">
                                {pkg.reasons.join(" · ")}
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    )}
                  </div>

                  {/* Completed Scan Pipeline Telemetry */}
                  <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4">
                    <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200 mb-2.5">
                      Scan Execution Telemetry ({activeReport.durationMs} ms)
                    </h2>
                    <div className="space-y-2">
                      {activeReport.stageLogs.map((st, idx) => (
                        <div
                          key={idx}
                          className="text-[11px] bg-[#090A0D] border border-zinc-800/70 rounded p-2"
                        >
                          <div className="flex items-center justify-between font-mono text-zinc-200">
                            <span className="flex items-center gap-1.5">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                              {st.stage}
                            </span>
                            <span className="text-zinc-500">
                              {st.durationMs}ms
                            </span>
                          </div>
                          <div className="text-zinc-400 mt-0.5 pl-4">
                            {st.detail}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 2. PROJECTS VIEW                                          */}
          {/* ========================================================= */}
          {activeNav === "projects" && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-semibold text-zinc-100">
                    Monitored Repositories & Benchmark Workspaces
                  </h2>
                  <p className="text-xs text-zinc-400">
                    Select any scanned repository or sample benchmark below to
                    inspect its full dependency graph, advisories, and
                    remediation plan.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setActiveNav("scan")}
                  className="px-3 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold text-xs flex items-center gap-1.5"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Scan New Repository
                </button>
              </div>

              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-zinc-800 bg-[#090A0D] text-[11px] font-mono uppercase text-zinc-400">
                      <th className="py-3 px-4">Project Name</th>
                      <th className="py-3 px-3">Origin</th>
                      <th className="py-3 px-3">Ecosystems</th>
                      <th className="py-3 px-3">Dependencies</th>
                      <th className="py-3 px-3">Findings</th>
                      <th className="py-3 px-3">Risk Score</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {reports.map((rep) => {
                      const isCurrent = rep.id === activeReport.id;
                      return (
                        <tr
                          key={rep.id}
                          className={
                            isCurrent
                              ? "bg-emerald-950/15"
                              : "hover:bg-zinc-900/50"
                          }
                        >
                          <td className="py-3 px-4">
                            <div className="font-mono font-semibold text-zinc-100">
                              {rep.projectName}
                            </div>
                            <div className="text-[11px] font-mono text-zinc-500">
                              {rep.repositoryUrl ?? "Uploaded Manifests"}
                            </div>
                          </td>
                          <td className="py-3 px-3">
                            {rep.isDemoData ? (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/70 text-amber-300 border border-amber-800/60">
                                SAMPLE BENCHMARK
                              </span>
                            ) : (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800/60">
                                LIVE SCAN ({rep.sourceType.toUpperCase()})
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-3 font-mono text-zinc-300">
                            {rep.ecosystems.join(", ") || "Workflow"}
                          </td>
                          <td className="py-3 px-3 font-mono text-zinc-200">
                            {rep.dependencies.length} pkgs
                          </td>
                          <td className="py-3 px-3 font-mono">
                            <span className="text-rose-400">
                              {rep.vulnerabilities.length} Vulns
                            </span>{" "}
                            ·{" "}
                            <span className="text-amber-300">
                              {rep.suspiciousPackages.length} Susp
                            </span>{" "}
                            ·{" "}
                            <span className="text-orange-300">
                              {rep.cicdFindings.length} CI/CD
                            </span>
                          </td>
                          <td className="py-3 px-3 font-mono">
                            <span
                              className={`font-bold ${
                                rep.riskScore.overallScore >= 70
                                  ? "text-rose-400"
                                  : rep.riskScore.overallScore >= 40
                                  ? "text-amber-400"
                                  : "text-emerald-400"
                              }`}
                            >
                              {rep.riskScore.overallScore}/100 (Grade{" "}
                              {rep.riskScore.postureGrade})
                            </span>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              type="button"
                              onClick={() => {
                                setActiveReportId(rep.id);
                                setActiveNav("overview");
                              }}
                              className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-100 font-mono text-[11px]"
                            >
                              {isCurrent ? "Active Workspace" : "Inspect →"}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 3. SCAN REPOSITORY WORKSTATION                            */}
          {/* ========================================================= */}
          {activeNav === "scan" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-8 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-5 space-y-5">
                <div>
                  <h2 className="text-base font-semibold text-zinc-100">
                    Supply Chain Security Scanner
                  </h2>
                  <p className="text-xs text-zinc-400 mt-0.5">
                    Analyze a public GitHub repository, upload dependency
                    manifests and lockfiles (npm, PyPI, RubyGems, Maven), or
                    import a CycloneDX / SPDX SBOM.
                  </p>
                </div>

                {/* Mode Selector Tabs */}
                <div className="grid grid-cols-3 gap-2 bg-[#090A0D] p-1 rounded-lg border border-zinc-800">
                  <button
                    type="button"
                    onClick={() => {
                      setScanTab("github");
                      setScanError(null);
                    }}
                    className={`py-2 px-3 rounded-md text-xs font-medium flex items-center justify-center gap-2 transition ${
                      scanTab === "github"
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/40"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <Globe className="w-3.5 h-3.5" />
                    Public GitHub URL
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setScanTab("upload");
                      setScanError(null);
                    }}
                    className={`py-2 px-3 rounded-md text-xs font-medium flex items-center justify-center gap-2 transition ${
                      scanTab === "upload"
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/40"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <Upload className="w-3.5 h-3.5" />
                    Upload Manifests / Lockfiles
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setScanTab("sbom");
                      setScanError(null);
                    }}
                    className={`py-2 px-3 rounded-md text-xs font-medium flex items-center justify-center gap-2 transition ${
                      scanTab === "sbom"
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/40"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <FileJson className="w-3.5 h-3.5" />
                    CycloneDX / SPDX SBOM
                  </button>
                </div>

                <form onSubmit={handleRunScan} className="space-y-4">
                  {scanTab === "github" ? (
                    <div className="space-y-3">
                      <div>
                        <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                          Public GitHub Repository URL (HTTPS enforced)
                        </label>
                        <input
                          type="text"
                          value={repoUrlInput}
                          onChange={(e) => setRepoUrlInput(e.target.value)}
                          placeholder="https://github.com/expressjs/express"
                          className="w-full bg-[#090A0D] border border-zinc-800 rounded-md px-3.5 py-2 text-xs font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-500"
                        />
                      </div>

                      <div className="flex flex-wrap items-center gap-2 text-[11px]">
                        <span className="text-zinc-500">Quick-fill public repos:</span>
                        {[
                          "https://github.com/expressjs/express",
                          "https://github.com/axios/axios",
                          "https://github.com/pallets/flask",
                        ].map((sampleUrl) => (
                          <button
                            key={sampleUrl}
                            type="button"
                            onClick={() => setRepoUrlInput(sampleUrl)}
                            className="font-mono px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300"
                          >
                            {sampleUrl.replace("https://github.com/", "")}
                          </button>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div className="border-2 border-dashed border-zinc-800 hover:border-emerald-500/50 rounded-lg p-6 text-center bg-[#090A0D] transition">
                        <Upload className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                        <div className="text-xs font-medium text-zinc-200">
                          {scanTab === "sbom"
                            ? "Select CycloneDX (.cdx.json, bom.json) or SPDX (.spdx.json) files"
                            : "Select dependency manifests, lockfiles, or CI/CD workflows"}
                        </div>
                        <p className="text-[11px] text-zinc-500 mt-1">
                          Supported: package.json, package-lock.json, yarn.lock,
                          pnpm-lock.yaml, requirements.txt, poetry.lock,
                          Pipfile.lock, Gemfile.lock, pom.xml, .github/workflows/*.yml
                        </p>
                        <label className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-100 text-xs font-medium cursor-pointer">
                          <span>Browse Local Files</span>
                          <input
                            type="file"
                            multiple
                            onChange={handleFileInputChange}
                            className="hidden"
                          />
                        </label>
                      </div>

                      {/* Quick load test fixture into uploader */}
                      <div className="flex flex-wrap items-center gap-2 text-[11px]">
                        <span className="text-zinc-500">
                          Or load test fixture files into scanner:
                        </span>
                        {SAMPLE_FIXTURE_PRESETS.map((preset) => (
                          <button
                            key={preset.id}
                            type="button"
                            onClick={() =>
                              handleLoadFixtureIntoUploader(preset.id)
                            }
                            className="font-mono px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-emerald-400"
                          >
                            Load {preset.name.split(" ")[0]}
                          </button>
                        ))}
                      </div>

                      {uploadedFiles.length > 0 && (
                        <div className="bg-[#090A0D] border border-zinc-800 rounded-md p-3 space-y-2">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono text-zinc-300">
                              Staged Files ({uploadedFiles.length})
                            </span>
                            <button
                              type="button"
                              onClick={() => setUploadedFiles([])}
                              className="text-[11px] text-rose-400 hover:underline flex items-center gap-1"
                            >
                              <Trash2 className="w-3 h-3" /> Clear All
                            </button>
                          </div>
                          <div className="divide-y divide-zinc-800/60 max-h-40 overflow-y-auto">
                            {uploadedFiles.map((f, i) => (
                              <div
                                key={i}
                                className="py-1.5 flex items-center justify-between text-xs font-mono"
                              >
                                <span className="text-zinc-200">{f.name}</span>
                                <span className="text-zinc-500">
                                  {(f.content.length / 1024).toFixed(1)} KB
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-zinc-400 mb-1">
                        Custom Project Label (Optional)
                      </label>
                      <input
                        type="text"
                        value={projectNameInput}
                        onChange={(e) => setProjectNameInput(e.target.value)}
                        placeholder="e.g., billing-service-prod"
                        className="w-full bg-[#090A0D] border border-zinc-800 rounded-md px-3 py-1.5 text-xs font-mono text-zinc-200"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-zinc-400 mb-1">
                        Internal Namespace Prefixes (Dependency Confusion)
                      </label>
                      <input
                        type="text"
                        value={customInternalPrefixes}
                        onChange={(e) =>
                          setCustomInternalPrefixes(e.target.value)
                        }
                        className="w-full bg-[#090A0D] border border-zinc-800 rounded-md px-3 py-1.5 text-xs font-mono text-zinc-200"
                      />
                    </div>
                  </div>

                  {scanError && (
                    <div className="bg-rose-950/40 border border-rose-800/80 rounded-md p-3 text-xs text-rose-200 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                      <div>
                        <div className="font-semibold">
                          Scan Validation / Execution Error
                        </div>
                        <div className="font-mono text-[11px] mt-0.5">
                          {scanError}
                        </div>
                      </div>
                    </div>
                  )}

                  {isScanning && (
                    <div className="bg-[#090A0D] border border-emerald-800/60 rounded-md p-3.5 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Executing Multi-Stage Supply Chain Scan...</span>
                      </div>
                      <div className="space-y-1 pl-5 text-[11px] font-mono text-zinc-400">
                        {activeScanStages.map((stage, idx) => (
                          <div key={idx}>✓ {stage}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={isScanning}
                    className="w-full py-2.5 rounded-md bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-zinc-950 font-semibold text-xs flex items-center justify-center gap-2 transition"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    {isScanning
                      ? "Analyzing Dependencies & Workflows..."
                      : "Execute Full Supply Chain Security Scan"}
                  </button>
                </form>
              </div>

              {/* Right Column: Security Guarantees & Supported Ecosystems */}
              <div className="lg:col-span-4 space-y-4">
                <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-200 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    Scanner Security Architecture
                  </h3>
                  <ul className="text-xs text-zinc-400 space-y-2 leading-relaxed">
                    <li>
                      • <strong className="text-zinc-200">Zero Code Execution:</strong>{" "}
                      SupplyGuard performs purely static AST/manifest parsing.
                      Uploaded scripts and CI workflows are never executed.
                    </li>
                    <li>
                      • <strong className="text-zinc-200">Strict SSRF Allowlisting:</strong>{" "}
                      Remote repository fetching only permits HTTPS requests to{" "}
                      <code className="font-mono text-zinc-300">github.com</code>{" "}
                      and blocks private/loopback IP ranges and open redirects.
                    </li>
                    <li>
                      • <strong className="text-zinc-200">Lockfile Prioritization:</strong>{" "}
                      When both a manifest (<code className="font-mono">package.json</code>)
                      and lockfile (<code className="font-mono">package-lock.json</code>)
                      are provided, deterministic resolved versions take precedence.
                    </li>
                  </ul>
                </div>

                {activeReport.unsupportedFiles.length > 0 && (
                  <div className="bg-amber-950/20 border border-amber-800/60 rounded-lg p-4 space-y-2">
                    <h3 className="text-xs font-semibold text-amber-300">
                      Skipped / Unsupported Files (
                      {activeReport.unsupportedFiles.length})
                    </h3>
                    {activeReport.unsupportedFiles.map((u, idx) => (
                      <div key={idx} className="text-[11px] text-zinc-300">
                        <span className="font-mono text-amber-200">
                          {u.fileName}:
                        </span>{" "}
                        {u.reason}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 4. VULNERABILITIES EXPLORER                               */}
          {/* ========================================================= */}
          {activeNav === "vulnerabilities" && (
            <div className="space-y-4">
              {/* Filter Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-3">
                <div className="flex flex-wrap items-center gap-2.5">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={vulnSearch}
                      onChange={(e) => setVulnSearch(e.target.value)}
                      placeholder="Filter by CVE, GHSA, or package..."
                      className="bg-[#090A0D] border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-200 w-64 focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                  <select
                    value={vulnSeverityFilter}
                    onChange={(e) => setVulnSeverityFilter(e.target.value)}
                    className="bg-[#090A0D] border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-300"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical Only</option>
                    <option value="HIGH">High Only</option>
                    <option value="MEDIUM">Medium Only</option>
                    <option value="LOW">Low Only</option>
                  </select>
                  <select
                    value={vulnScopeFilter}
                    onChange={(e) => setVulnScopeFilter(e.target.value)}
                    className="bg-[#090A0D] border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-300"
                  >
                    <option value="ALL">Direct & Transitive</option>
                    <option value="direct">Direct Dependencies Only</option>
                    <option value="transitive">Transitive Only</option>
                  </select>
                </div>

                <div className="text-xs font-mono text-zinc-400">
                  Intelligence Source:{" "}
                  <span className="text-emerald-400">
                    {activeReport.intelligenceStatus.osvLiveQueried
                      ? "OSV.dev Live API + Verified Advisories"
                      : "Verified Advisory Engine"}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                <div
                  className={`${
                    selectedVuln ? "lg:col-span-7" : "lg:col-span-12"
                  } bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden`}
                >
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-zinc-800 bg-[#090A0D] text-[11px] font-mono uppercase text-zinc-400">
                          <th className="py-3 px-4">Severity</th>
                          <th className="py-3 px-3">Vulnerability ID</th>
                          <th className="py-3 px-3">Package</th>
                          <th className="py-3 px-3">Installed</th>
                          <th className="py-3 px-3">Fixed Version</th>
                          <th className="py-3 px-3">Dependency Type</th>
                          <th className="py-3 px-4">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/60">
                        {filteredVulnerabilities.length === 0 ? (
                          <tr>
                            <td
                              colSpan={7}
                              className="py-8 text-center text-zinc-400"
                            >
                              No vulnerability findings match the current filter
                              criteria.
                            </td>
                          </tr>
                        ) : (
                          filteredVulnerabilities.map((v) => (
                            <tr
                              key={`${v.id}-${v.packageName}`}
                              onClick={() => setSelectedVuln(v)}
                              className={`cursor-pointer transition ${
                                selectedVuln?.id === v.id &&
                                selectedVuln?.packageName === v.packageName
                                  ? "bg-emerald-950/20"
                                  : "hover:bg-zinc-900/60"
                              }`}
                            >
                              <td className="py-3 px-4">
                                <span
                                  className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                                    SEVERITY_BADGE_STYLES[v.severity]
                                  }`}
                                >
                                  {v.severity}
                                  {v.cvssScore !== null
                                    ? ` · ${v.cvssScore}`
                                    : ""}
                                </span>
                              </td>
                              <td className="py-3 px-3 font-mono font-semibold text-zinc-100">
                                <div>{v.cveId ?? v.id}</div>
                                {v.ghsaId && v.cveId && (
                                  <div className="text-[10px] text-zinc-500">
                                    {v.ghsaId}
                                  </div>
                                )}
                              </td>
                              <td className="py-3 px-3 font-mono text-zinc-200">
                                {v.packageName}
                                <span className="ml-1.5 text-[10px] text-zinc-500">
                                  ({v.ecosystem})
                                </span>
                              </td>
                              <td className="py-3 px-3 font-mono text-rose-300">
                                {v.installedVersion}
                              </td>
                              <td className="py-3 px-3 font-mono text-emerald-400">
                                {v.fixedVersion ?? "Unpatched"}
                              </td>
                              <td className="py-3 px-3 font-mono">
                                <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                                  {v.dependencyScope}
                                </span>
                              </td>
                              <td className="py-3 px-4 font-mono text-[11px] text-zinc-300">
                                {v.fixedVersion
                                  ? "Patch Available"
                                  : "Review Workaround"}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Vulnerability Detail Inspector Drawer */}
                {selectedVuln && (
                  <div className="lg:col-span-5 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-5 space-y-4">
                    <div className="flex items-start justify-between border-b border-zinc-800 pb-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                              SEVERITY_BADGE_STYLES[selectedVuln.severity]
                            }`}
                          >
                            {selectedVuln.severity}
                          </span>
                          <span className="font-mono text-sm font-bold text-zinc-100">
                            {selectedVuln.cveId ?? selectedVuln.id}
                          </span>
                        </div>
                        <h3 className="text-sm font-semibold text-zinc-200 mt-1.5">
                          {selectedVuln.title}
                        </h3>
                      </div>
                      <button
                        type="button"
                        onClick={() => setSelectedVuln(null)}
                        className="p-1 text-zinc-400 hover:text-zinc-200"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
                      <div className="bg-[#090A0D] border border-zinc-800 rounded p-2.5">
                        <div className="text-[10px] text-zinc-500">
                          AFFECTED PACKAGE
                        </div>
                        <div className="text-zinc-100 mt-0.5">
                          {selectedVuln.packageName}@{selectedVuln.installedVersion}
                        </div>
                      </div>
                      <div className="bg-[#090A0D] border border-zinc-800 rounded p-2.5">
                        <div className="text-[10px] text-zinc-500">
                          VULNERABLE RANGE
                        </div>
                        <div className="text-rose-300 mt-0.5">
                          {selectedVuln.vulnerableRange}
                        </div>
                      </div>
                      <div className="bg-[#090A0D] border border-zinc-800 rounded p-2.5">
                        <div className="text-[10px] text-zinc-500">
                          PATCHED VERSION
                        </div>
                        <div className="text-emerald-400 mt-0.5">
                          {selectedVuln.fixedVersion ?? "No Fix Published"}
                        </div>
                      </div>
                      <div className="bg-[#090A0D] border border-zinc-800 rounded p-2.5">
                        <div className="text-[10px] text-zinc-500">
                          CVSS v3 SCORE
                        </div>
                        <div className="text-zinc-100 mt-0.5">
                          {selectedVuln.cvssScore !== null
                            ? `${selectedVuln.cvssScore} / 10.0`
                            : "Not Specified"}
                        </div>
                      </div>
                    </div>

                    {selectedVuln.cvssVector && (
                      <div className="text-[11px] font-mono bg-[#090A0D] border border-zinc-800 rounded px-3 py-2 text-zinc-400 break-all">
                        Vector: {selectedVuln.cvssVector}
                      </div>
                    )}

                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-1">
                        Dependency Exposure Path
                      </div>
                      <div className="text-xs font-mono bg-[#090A0D] border border-zinc-800 rounded p-2.5 text-zinc-200">
                        {selectedVuln.dependencyPath.join(" → ")} (
                        {selectedVuln.dependencyScope})
                      </div>
                    </div>

                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-1">
                        Technical Description
                      </div>
                      <p className="text-xs text-zinc-300 leading-relaxed">
                        {selectedVuln.description}
                      </p>
                    </div>

                    <div className="bg-emerald-950/20 border border-emerald-800/60 rounded p-3">
                      <div className="text-xs font-semibold text-emerald-300 mb-1">
                        Recommended Remediation
                      </div>
                      <p className="text-xs text-zinc-200">
                        {selectedVuln.remediation}
                      </p>
                    </div>

                    {selectedVuln.references.length > 0 && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-1.5">
                          Advisory References
                        </div>
                        <div className="space-y-1">
                          {selectedVuln.references.map((refUrl, idx) => (
                            <a
                              key={idx}
                              href={refUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs font-mono text-emerald-400 hover:underline flex items-center gap-1 break-all"
                            >
                              <ExternalLink className="w-3 h-3 shrink-0" />
                              {refUrl}
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 5. DEPENDENCIES & REACT FLOW GRAPH                        */}
          {/* ========================================================= */}
          {activeNav === "dependencies" && (
            <DependencyGraphView report={activeReport} />
          )}

          {/* ========================================================= */}
          {/* 6. SUPPLY CHAIN RISKS (TYPOSQUATTING & CONFUSION)         */}
          {/* ========================================================= */}
          {activeNav === "supply-chain" && (
            <div className="space-y-6">
              {/* Important Methodological Banner */}
              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 flex items-start gap-3">
                <AlertOctagon className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div className="text-xs text-zinc-300 space-y-1">
                  <div className="font-semibold text-zinc-100">
                    Evidence-Based Malicious Indicator & Namespace Confusion
                    Engine
                  </div>
                  <p className="text-zinc-400 leading-relaxed">
                    A similar package name (Levenshtein edit distance or
                    phonetic similarity) is a risk indicator, not standalone
                    proof of malicious intent. SupplyGuard displays the concrete
                    technical evidence behind every finding (edit distance,
                    homograph code points, lifecycle install hooks, and registry
                    scope configuration) so security engineers can verify
                    provenance.
                  </p>
                </div>
              </div>

              {/* Suspicious Package & Typosquatting Findings */}
              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                    Suspicious Package & Typosquatting Indicators (
                    {activeReport.suspiciousPackages.length})
                  </h3>
                </div>
                {activeReport.suspiciousPackages.length === 0 ? (
                  <div className="p-6 text-center text-xs text-zinc-400">
                    No typosquatting, homograph, or suspicious install-hook
                    indicators detected.
                  </div>
                ) : (
                  <div className="divide-y divide-zinc-800/60">
                    {activeReport.suspiciousPackages.map((susp) => (
                      <div key={susp.id} className="p-4 space-y-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5">
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                                SEVERITY_BADGE_STYLES[susp.severity]
                              }`}
                            >
                              {susp.severity}
                            </span>
                            <span className="font-mono text-sm font-bold text-zinc-100">
                              {susp.packageName}@{susp.version}
                            </span>
                            <span className="text-xs font-mono text-zinc-400">
                              ({susp.ecosystem} · {susp.sourceFile})
                            </span>
                          </div>
                          <div className="flex items-center gap-2 font-mono text-xs">
                            <span className="px-2.5 py-1 rounded bg-amber-950/80 border border-amber-700/70 text-amber-300 font-semibold">
                              Suspicion Score: {susp.suspicionScore} / 100
                            </span>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                          {susp.indicators.map((ind, idx) => (
                            <div
                              key={idx}
                              className="bg-[#090A0D] border border-zinc-800/80 rounded p-3 text-xs space-y-1"
                            >
                              <div className="flex items-center justify-between font-mono text-[11px] text-amber-300">
                                <span>{ind.type}</span>
                                <span>+{ind.weight} weight</span>
                              </div>
                              <p className="text-zinc-300">{ind.description}</p>
                              <div className="font-mono text-[11px] text-zinc-400 bg-zinc-900/90 px-2 py-1 rounded mt-1 break-all">
                                Evidence: {ind.evidence}
                              </div>
                            </div>
                          ))}
                        </div>

                        <div className="bg-emerald-950/20 border border-emerald-800/50 rounded p-2.5 text-xs text-zinc-200">
                          <strong className="text-emerald-400">
                            Recommended Action:
                          </strong>{" "}
                          {susp.remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Dependency Confusion Findings */}
              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                    Potential Dependency Confusion Exposure (
                    {activeReport.dependencyConfusion.length})
                  </h3>
                </div>
                {activeReport.dependencyConfusion.length === 0 ? (
                  <div className="p-6 text-center text-xs text-zinc-400">
                    No unscoped internal package names or insecure multi-index
                    registry configurations detected.
                  </div>
                ) : (
                  <div className="divide-y divide-zinc-800/60">
                    {activeReport.dependencyConfusion.map((dc) => (
                      <div key={dc.id} className="p-4 space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                                SEVERITY_BADGE_STYLES[dc.severity]
                              }`}
                            >
                              {dc.severity}
                            </span>
                            <span className="font-mono text-sm font-semibold text-zinc-100">
                              {dc.packageName}
                            </span>
                            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                              {dc.riskType}
                            </span>
                          </div>
                          <span className="text-xs font-mono text-zinc-400">
                            File: {dc.sourceFile}
                          </span>
                        </div>
                        <div className="text-xs font-mono text-amber-200/90 bg-[#090A0D] border border-zinc-800 rounded px-3 py-1.5">
                          Evidence: {dc.evidence}
                        </div>
                        <p className="text-xs text-zinc-300">{dc.explanation}</p>
                        <div className="text-xs text-emerald-300 font-medium">
                          Remediation: {dc.remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 7. CI/CD PIPELINE SECURITY                                */}
          {/* ========================================================= */}
          {activeNav === "cicd" && (
            <div className="space-y-4">
              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-zinc-100">
                    CI/CD Pipeline Static Security Analyzer
                  </h2>
                  <p className="text-xs text-zinc-400">
                    Detects unpinned GitHub Actions, mutable tags, excessive
                    GITHUB_TOKEN permissions, pull_request_target hazards, and
                    command injection interpolations without executing workflows.
                  </p>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
                  {activeReport.cicdFindings.length} finding(s)
                </span>
              </div>

              {activeReport.cicdFindings.length === 0 ? (
                <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-8 text-center text-xs text-zinc-400">
                  No CI/CD pipeline misconfigurations detected in scanned
                  workflow files.
                </div>
              ) : (
                <div className="space-y-3">
                  {activeReport.cicdFindings.map((c) => (
                    <div
                      key={c.id}
                      className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 space-y-2.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                              SEVERITY_BADGE_STYLES[c.severity]
                            }`}
                          >
                            {c.severity}
                          </span>
                          <span className="font-mono text-xs text-emerald-400">
                            [{c.ruleId}]
                          </span>
                          <h3 className="text-sm font-semibold text-zinc-100">
                            {c.title}
                          </h3>
                        </div>
                        <span className="text-xs font-mono text-zinc-400">
                          {c.platform} · {c.filePath}:L{c.lineNumber}
                        </span>
                      </div>

                      <div className="bg-[#090A0D] border border-zinc-800 rounded px-3 py-2 font-mono text-xs text-rose-300 overflow-x-auto">
                        <span className="text-zinc-600 select-none mr-3">
                          {c.lineNumber} |
                        </span>
                        {c.snippet}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="bg-[#090A0D] border border-zinc-800/70 rounded p-3">
                          <div className="font-semibold text-zinc-300 mb-1">
                            Supply Chain Risk Explanation
                          </div>
                          <p className="text-zinc-400 leading-relaxed">
                            {c.riskExplanation}
                          </p>
                        </div>
                        <div className="bg-emerald-950/15 border border-emerald-800/50 rounded p-3">
                          <div className="font-semibold text-emerald-400 mb-1">
                            Recommended Hardening
                          </div>
                          <p className="text-zinc-300 leading-relaxed">
                            {c.remediation}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ========================================================= */}
          {/* 8. SECRETS DETECTION                                      */}
          {/* ========================================================= */}
          {activeNav === "secrets" && (
            <div className="space-y-4">
              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold text-zinc-100">
                    Static Credential & High-Entropy Secret Scanner
                  </h2>
                  <p className="text-xs text-zinc-400">
                    All discovered credentials are strictly masked upon
                    detection, never stored in raw form, and never transmitted
                    to external APIs.
                  </p>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-rose-950/60 border border-rose-800/60 text-rose-300">
                  Redaction Policy: STRICT MASKING ACTIVE
                </span>
              </div>

              {activeReport.secretFindings.length === 0 ? (
                <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-8 text-center text-xs text-zinc-400">
                  Zero hardcoded secrets or high-entropy credentials detected in
                  scanned files.
                </div>
              ) : (
                <div className="space-y-3">
                  {activeReport.secretFindings.map((sec) => (
                    <div
                      key={sec.id}
                      className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 space-y-2.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                              SEVERITY_BADGE_STYLES[sec.severity]
                            }`}
                          >
                            {sec.severity}
                          </span>
                          <span className="font-mono text-xs text-zinc-400">
                            [{sec.ruleId}]
                          </span>
                          <h3 className="text-sm font-semibold text-zinc-100">
                            {sec.secretType}
                          </h3>
                        </div>
                        <span className="text-xs font-mono text-zinc-400">
                          {sec.filePath}:L{sec.lineNumber} · Entropy:{" "}
                          {sec.entropy} bits/char · Confidence: {sec.confidence}
                        </span>
                      </div>

                      <div className="bg-[#090A0D] border border-zinc-800 rounded px-3 py-2 font-mono text-xs text-amber-300">
                        Masked Credential Preview: {sec.maskedValue}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="bg-[#090A0D] border border-zinc-800/70 rounded p-2.5">
                          <span className="font-semibold text-zinc-300">
                            False Positive Assessment:{" "}
                          </span>
                          <span className="text-zinc-400">
                            {sec.falsePositiveNote}
                          </span>
                        </div>
                        <div className="bg-emerald-950/15 border border-emerald-800/50 rounded p-2.5">
                          <span className="font-semibold text-emerald-400">
                            Remediation:{" "}
                          </span>
                          <span className="text-zinc-300">
                            {sec.remediation}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ========================================================= */}
          {/* 9. LICENSE COMPLIANCE                                     */}
          {/* ========================================================= */}
          {activeNav === "licenses" && (
            <div className="space-y-4">
              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-4 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h2 className="text-sm font-semibold text-zinc-100">
                    Open-Source License Compliance Identification
                  </h2>
                  <select
                    value={licenseCategoryFilter}
                    onChange={(e) => setLicenseCategoryFilter(e.target.value)}
                    className="bg-[#090A0D] border border-zinc-800 rounded px-2.5 py-1.5 text-xs text-zinc-200 font-mono"
                  >
                    <option value="ALL">
                      All Categories ({activeReport.licenseFindings.length})
                    </option>
                    <option value="RESTRICTIVE">
                      Copyleft / Restrictive Only
                    </option>
                    <option value="PERMISSIVE">Permissive Only</option>
                    <option value="UNKNOWN">Unknown / Unclassified Only</option>
                  </select>
                </div>
                <p className="text-[11px] text-zinc-400 font-mono bg-[#090A0D] border border-zinc-800/80 rounded p-2.5">
                  {LICENSE_LEGAL_DISCLAIMER}
                </p>
              </div>

              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-zinc-800 bg-[#090A0D] text-[11px] font-mono uppercase text-zinc-400">
                      <th className="py-3 px-4">Package</th>
                      <th className="py-3 px-3">Ecosystem</th>
                      <th className="py-3 px-3">SPDX Identifier</th>
                      <th className="py-3 px-3">Classification</th>
                      <th className="py-3 px-4">Technical Notes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {activeReport.licenseFindings
                      .filter((l) => {
                        if (licenseCategoryFilter === "ALL") return true;
                        if (licenseCategoryFilter === "RESTRICTIVE")
                          return l.isRestrictive;
                        return l.category === licenseCategoryFilter;
                      })
                      .map((lic) => (
                        <tr key={lic.id} className="hover:bg-zinc-900/50">
                          <td className="py-2.5 px-4 font-mono text-zinc-100">
                            {lic.packageName}@{lic.version}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-zinc-400">
                            {lic.ecosystem}
                          </td>
                          <td className="py-2.5 px-3 font-mono font-semibold text-zinc-200">
                            {lic.spdxId}
                          </td>
                          <td className="py-2.5 px-3 font-mono">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded ${
                                lic.isRestrictive
                                  ? "bg-amber-950/80 text-amber-300 border border-amber-700/70"
                                  : lic.category === "PERMISSIVE"
                                  ? "bg-emerald-950/70 text-emerald-300 border border-emerald-800/60"
                                  : "bg-zinc-800 text-zinc-400"
                              }`}
                            >
                              {lic.category}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-zinc-400">
                            {lic.notes}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 10. REPORTS & CYCLONEDX SBOM EXPORT                       */}
          {/* ========================================================= */}
          {activeNav === "reports" && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-5 flex flex-col justify-between space-y-4">
                  <div>
                    <div className="w-9 h-9 rounded-md bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mb-3">
                      <FileText className="w-5 h-5 text-emerald-400" />
                    </div>
                    <h3 className="text-sm font-semibold text-zinc-100">
                      Executive & Technical PDF Report
                    </h3>
                    <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                      Formatted multi-page assessment report containing posture
                      summary, domain risk breakdown, CVE table, supply chain
                      indicators, CI/CD & secret findings, and methodology
                      disclosures.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => downloadPdfSecurityReport(activeReport)}
                    className="w-full py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold text-xs flex items-center justify-center gap-1.5"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download PDF Report
                  </button>
                </div>

                <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-5 flex flex-col justify-between space-y-4">
                  <div>
                    <div className="w-9 h-9 rounded-md bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mb-3">
                      <Code2 className="w-5 h-5 text-emerald-400" />
                    </div>
                    <h3 className="text-sm font-semibold text-zinc-100">
                      Full Security Assessment JSON
                    </h3>
                    <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                      Complete machine-readable JSON export containing all 12
                      report sections for SIEM ingestion, compliance archives,
                      or automated CI/CD policy gates.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleDownloadJsonReport}
                    className="w-full py-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-100 font-semibold text-xs flex items-center justify-center gap-1.5 border border-zinc-700"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    Download Assessment JSON
                  </button>
                </div>

                <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg p-5 flex flex-col justify-between space-y-4">
                  <div>
                    <div className="w-9 h-9 rounded-md bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mb-3">
                      <FileJson className="w-5 h-5 text-emerald-400" />
                    </div>
                    <h3 className="text-sm font-semibold text-zinc-100">
                      CycloneDX v1.5 SBOM + VDR
                    </h3>
                    <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                      Standards-compliant CycloneDX 1.5 Software Bill of
                      Materials with Package URLs (purl), SPDX license IDs,
                      dependency graph edges, and embedded vulnerability
                      ratings.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleDownloadCycloneDx}
                    className="w-full py-2 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-100 font-semibold text-xs flex items-center justify-center gap-1.5 border border-zinc-700"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    Export CycloneDX 1.5 (.cdx.json)
                  </button>
                </div>
              </div>

              {/* Live CycloneDX SBOM Preview */}
              <div className="bg-[#0E1015] border border-zinc-800/80 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-zinc-200">
                    Live CycloneDX 1.5 SBOM Preview ({activeReport.projectName})
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      handleCopy(
                        JSON.stringify(
                          generateCycloneDxSbom(activeReport),
                          null,
                          2
                        ),
                        "sbom-preview"
                      )
                    }
                    className="text-xs font-mono text-emerald-400 hover:underline flex items-center gap-1"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    {copiedText === "sbom-preview" ? "Copied JSON" : "Copy SBOM"}
                  </button>
                </div>
                <pre className="p-4 text-[11px] font-mono text-zinc-300 bg-[#090A0D] max-h-96 overflow-auto">
                  {JSON.stringify(generateCycloneDxSbom(activeReport), null, 2)}
                </pre>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* 11. SETTINGS & RISK SCORING METHODOLOGY CONFIG            */}
          {/* ========================================================= */}
          {activeNav === "settings" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-7 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-5 space-y-5">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div>
                    <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                      <Sliders className="w-4 h-4 text-emerald-400" />
                      Configurable Composite Risk Scoring Weights
                    </h2>
                    <p className="text-xs text-zinc-400 mt-0.5">
                      Adjust the relative domain weights below to immediately
                      recompute the project&apos;s normalized 0–100 risk score.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setRiskWeights(DEFAULT_RISK_WEIGHTS)}
                    className="text-xs font-mono px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200"
                  >
                    Reset Defaults
                  </button>
                </div>

                <div className="space-y-4 text-xs">
                  {(
                    [
                      {
                        key: "vulnerabilities",
                        label: "Vulnerability Intelligence (CVEs / GHSAs)",
                      },
                      {
                        key: "supplyChainAndTyposquat",
                        label:
                          "Malicious Package & Typosquatting Indicators",
                      },
                      {
                        key: "secrets",
                        label: "Static Secret & Credential Exposure",
                      },
                      {
                        key: "cicd",
                        label: "CI/CD Workflow Security Findings",
                      },
                      {
                        key: "licenseAndConfusion",
                        label:
                          "Dependency Confusion & Restrictive Licenses",
                      },
                    ] as const
                  ).map((item) => (
                    <div key={item.key} className="space-y-1">
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-zinc-200">{item.label}</span>
                        <span className="text-emerald-400">
                          {Math.round(riskWeights[item.key] * 100)}%
                        </span>
                      </div>
                      <input
                        type="range"
                        min={0.05}
                        max={0.8}
                        step={0.05}
                        value={riskWeights[item.key]}
                        onChange={(e) =>
                          setRiskWeights((prev) => ({
                            ...prev,
                            [item.key]: parseFloat(e.target.value),
                          }))
                        }
                        className="w-full accent-emerald-500 cursor-pointer"
                      />
                    </div>
                  ))}
                </div>

                <div className="bg-[#090A0D] border border-zinc-800 rounded p-3.5 text-xs space-y-1.5">
                  <div className="font-semibold text-zinc-200">
                    Explainable Risk Scoring Methodology
                  </div>
                  <p className="text-zinc-400 leading-relaxed">
                    {activeReport.riskScore.methodologySummary}
                  </p>
                </div>
              </div>

              <div className="lg:col-span-5 bg-[#0E1015] border border-zinc-800/80 rounded-lg p-5 space-y-4">
                <h3 className="text-sm font-semibold text-zinc-100">
                  Live Recalculated Score Preview
                </h3>
                <div className="bg-[#090A0D] border border-zinc-800 rounded-lg p-4 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-mono text-zinc-400">
                      {activeReport.projectName}
                    </div>
                    <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                      {activeReport.riskScore.overallScore} / 100
                    </div>
                  </div>
                  <div className="text-right font-mono">
                    <div className="text-lg font-bold text-zinc-100">
                      Grade {activeReport.riskScore.postureGrade}
                    </div>
                    <div className="text-xs text-zinc-400">
                      {activeReport.riskScore.postureLabel}
                    </div>
                  </div>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  {activeReport.riskScore.categoryScores.map((cat) => (
                    <div
                      key={cat.category}
                      className="flex items-center justify-between bg-[#090A0D] border border-zinc-800/70 rounded px-3 py-2"
                    >
                      <span className="text-zinc-300">{cat.category}</span>
                      <span className="text-zinc-100">
                        {cat.normalizedScore}/100 × {Math.round(cat.weight * 100)}%
                        = {cat.weightedContribution} pts
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
