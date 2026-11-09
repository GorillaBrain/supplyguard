import { ScanReport, ScanStageLog } from "@/types/security";
import { parseProjectFiles } from "@/lib/parsers";
import { scanVulnerabilities } from "@/lib/scanners/osv";
import { detectSuspiciousPackages } from "@/lib/scanners/typosquatting";
import { analyzeDependencyConfusion } from "@/lib/scanners/dependency-confusion";
import { analyzeCiCdFiles } from "@/lib/scanners/cicd";
import { scanForSecrets } from "@/lib/scanners/secrets";
import { analyzeLicenses } from "@/lib/scanners/licenses";
import { calculateProjectRiskScore } from "@/lib/scanners/risk-score";

export async function runFullSecurityScan(params: {
  projectName: string;
  sourceType: ScanReport["sourceType"];
  repositoryUrl?: string;
  isDemoData?: boolean;
  files: { name: string; content: string }[];
  internalPrefixes?: string[];
  skipNetwork?: boolean;
}): Promise<ScanReport> {
  const startTotal = Date.now();
  const stageLogs: ScanStageLog[] = [];

  // Stage 1-6: Parse dependency manifests, lockfiles, SBOMs, and build graph
  const tParse = Date.now();
  const parsedGraph = parseProjectFiles(params.files);
  stageLogs.push({
    stage: "Manifest, Lockfile & Dependency Graph Resolution",
    status: parsedGraph.dependencies.length > 0 ? "completed" : "warning",
    durationMs: Math.max(1, Date.now() - tParse),
    detail: `Parsed ${parsedGraph.parsedFiles.length} file(s) across [${
      parsedGraph.ecosystems.join(", ") || "config/workflow"
    }]; resolved ${parsedGraph.dependencies.length} dependencies and ${
      parsedGraph.edges.length
    } graph edges.`,
  });

  // Stage 7: Vulnerability Intelligence (OSV.dev + Verified Advisory Engine)
  const tVuln = Date.now();
  const vulnResult = await scanVulnerabilities(parsedGraph.dependencies, {
    skipNetwork: params.skipNetwork,
  });
  stageLogs.push({
    stage: "OSV.dev & Advisory Vulnerability Matching",
    status: "completed",
    durationMs: Math.max(1, Date.now() - tVuln),
    detail: `Evaluated ${parsedGraph.dependencies.length} package versions; matched ${vulnResult.findings.length} vulnerability advisory(s).`,
  });

  // Stage 8: Suspicious Package & Typosquatting Analysis
  const tSusp = Date.now();
  const suspiciousPackages = detectSuspiciousPackages(parsedGraph.dependencies);
  stageLogs.push({
    stage: "Malicious Indicator & Typosquatting Heuristic Analysis",
    status: "completed",
    durationMs: Math.max(1, Date.now() - tSusp),
    detail: `Inspected edit distance, phonetic skeletons, homographs, and lifecycle scripts; flagged ${suspiciousPackages.length} package indicator(s).`,
  });

  // Stage 9: Dependency Confusion Analysis
  const tConf = Date.now();
  const dependencyConfusion = analyzeDependencyConfusion(
    parsedGraph.dependencies,
    parsedGraph.registryConfigs,
    params.files,
    params.internalPrefixes
  );
  stageLogs.push({
    stage: "Dependency Confusion & Namespace Scope Audit",
    status: "completed",
    durationMs: Math.max(1, Date.now() - tConf),
    detail: `Analyzed internal naming conventions and registry configs; identified ${dependencyConfusion.length} potential exposure(s).`,
  });

  // Stage 10: License Compliance Analysis
  const tLic = Date.now();
  const licenseFindings = analyzeLicenses(parsedGraph.dependencies);
  const restrictiveCount = licenseFindings.filter((l) => l.isRestrictive).length;
  stageLogs.push({
    stage: "SPDX Open-Source License Classification",
    status: "completed",
    durationMs: Math.max(1, Date.now() - tLic),
    detail: `Classified licenses for ${licenseFindings.length} packages (${restrictiveCount} copyleft/restrictive).`,
  });

  // Stage 11: CI/CD Workflow Static Security Analysis
  const tCicd = Date.now();
  const cicdFindings = analyzeCiCdFiles(params.files);
  stageLogs.push({
    stage: "CI/CD Pipeline Static Security Analysis",
    status: "completed",
    durationMs: Math.max(1, Date.now() - tCicd),
    detail: `Audited workflow configurations; detected ${cicdFindings.length} pipeline security issue(s).`,
  });

  // Stage 12: Static Secret Detection & Redaction
  const tSec = Date.now();
  const secretFindings = scanForSecrets(params.files);
  stageLogs.push({
    stage: "Static Entropy & Pattern Secret Detection",
    status: "completed",
    durationMs: Math.max(1, Date.now() - tSec),
    detail: `Scanned non-lockfile sources; detected and masked ${secretFindings.length} exposed credential(s).`,
  });

  // Stage 13: Explainable Composite Risk Scoring & Remediation Synthesis
  const tRisk = Date.now();
  const riskScore = calculateProjectRiskScore({
    dependencies: parsedGraph.dependencies,
    vulnerabilities: vulnResult.findings,
    suspiciousPackages,
    dependencyConfusion,
    cicdFindings,
    secretFindings,
    licenseFindings,
  });
  stageLogs.push({
    stage: "Composite Risk Scoring & Remediation Prioritization",
    status: "completed",
    durationMs: Math.max(1, Date.now() - tRisk),
    detail: `Computed normalized project risk score ${riskScore.overallScore}/100 (Grade ${riskScore.postureGrade}) with ${riskScore.prioritizedRemediations.length} prioritized remediations.`,
  });

  const totalDuration = Math.max(1, Date.now() - startTotal);

  return {
    id: `SCAN-${Date.now().toString(36).toUpperCase()}-${Math.random()
      .toString(36)
      .slice(2, 6)
      .toUpperCase()}`,
    projectName: params.projectName,
    sourceType: params.sourceType,
    repositoryUrl: params.repositoryUrl,
    scannedAt: new Date().toISOString(),
    durationMs: totalDuration,
    isDemoData: Boolean(params.isDemoData),
    ecosystems: parsedGraph.ecosystems,
    scannedFiles: parsedGraph.parsedFiles,
    unsupportedFiles: parsedGraph.unsupportedFiles,
    intelligenceStatus: {
      osvLiveQueried: vulnResult.osvLiveQueried,
      osvPackagesQueried: vulnResult.osvPackagesQueried,
      registryMetadataLive: vulnResult.osvLiveQueried,
      notes: vulnResult.notes,
    },
    dependencies: parsedGraph.dependencies,
    edges: parsedGraph.edges,
    vulnerabilities: vulnResult.findings,
    suspiciousPackages,
    dependencyConfusion,
    cicdFindings,
    secretFindings,
    licenseFindings,
    riskScore,
    stageLogs,
  };
}
