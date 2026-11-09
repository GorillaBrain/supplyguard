export type Ecosystem = "npm" | "PyPI" | "RubyGems" | "Maven" | "SBOM";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type DependencyScope = "direct" | "transitive";

export interface DependencyNode {
  id: string; // e.g., "npm:lodash@4.17.15"
  name: string;
  version: string;
  ecosystem: Ecosystem;
  scope: DependencyScope;
  depth: number;
  license?: string;
  resolvedUrl?: string;
  integrity?: string;
  hasInstallScripts?: boolean;
  installScriptContent?: string;
  parents: string[]; // IDs of parent nodes
  children: string[]; // IDs of child nodes
  sourceFile: string;
  publishedAt?: string;
  maintainerCount?: number;
}

export interface DependencyEdge {
  id: string;
  source: string;
  target: string;
  scope: DependencyScope;
}

export interface VulnerabilityFinding {
  id: string; // Primary ID (e.g., GHSA-xxxx or CVE-xxxx)
  cveId: string | null;
  ghsaId: string | null;
  aliases: string[];
  packageName: string;
  installedVersion: string;
  ecosystem: Ecosystem;
  vulnerableRange: string;
  fixedVersion: string | null;
  severity: Severity;
  cvssScore: number | null;
  cvssVector: string | null;
  title: string;
  description: string;
  references: string[];
  publishedAt?: string;
  dependencyScope: DependencyScope;
  dependencyPath: string[];
  remediation: string;
  exploitability: "KNOWN_EXPLOITED" | "HIGH_PROBABILITY" | "STANDARD" | "UNPROVEN";
  source: "OSV.dev" | "GitHub Advisory" | "Verified Offline Intelligence";
}

export interface SuspiciousIndicator {
  type:
    | "TYPOSQUATTING_LEVENSHTEIN"
    | "PHONETIC_SIMILARITY"
    | "UNICODE_HOMOGRAPH"
    | "SUSPICIOUS_NAMING_CONVENTION"
    | "SUSPICIOUS_INSTALL_SCRIPT"
    | "EXTERNAL_NETWORK_CALL"
    | "NEWLY_PUBLISHED_PACKAGE"
    | "UNUSUAL_VERSION_ANOMALY"
    | "METADATA_ANOMALY";
  description: string;
  evidence: string;
  weight: number;
}

export interface SuspiciousPackageFinding {
  id: string;
  packageName: string;
  version: string;
  ecosystem: Ecosystem;
  suspicionScore: number; // 0 to 100
  severity: Severity;
  classification:
    | "HIGH_RISK_INDICATORS"
    | "MODERATE_ANOMALY"
    | "LOW_SIMILARITY_INDICATOR";
  similarLegitimatePackage?: string;
  editDistance?: number;
  indicators: SuspiciousIndicator[];
  sourceFile: string;
  remediation: string;
}

export interface DependencyConfusionFinding {
  id: string;
  packageName: string;
  version: string;
  ecosystem: Ecosystem;
  severity: Severity;
  riskType:
    | "UNSCOPED_INTERNAL_NAMING"
    | "INSECURE_REGISTRY_MIXING"
    | "PUBLIC_NAMESPACE_COLLISION_RISK"
    | "MISSING_SCOPE_MAPPING";
  evidence: string;
  sourceFile: string;
  explanation: string;
  remediation: string;
}

export interface CiCdFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  platform: "GitHub Actions" | "GitLab CI" | "Jenkins";
  filePath: string;
  lineNumber: number;
  snippet: string;
  description: string;
  riskExplanation: string;
  remediation: string;
}

export interface SecretFinding {
  id: string;
  ruleId: string;
  secretType:
    | "AWS Access Key ID"
    | "AWS Secret Key"
    | "GitHub Personal Access Token"
    | "Slack Webhook / Bot Token"
    | "Private Key Material"
    | "Database Connection URI"
    | "Stripe Live API Key"
    | "JWT Bearer Token"
    | "Generic High-Entropy API Secret";
  severity: Severity;
  filePath: string;
  lineNumber: number;
  maskedValue: string; // Strictly masked, never raw
  entropy: number;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  falsePositiveNote: string;
  remediation: string;
}

export type LicenseCategory =
  | "PERMISSIVE"
  | "WEAK_COPYLEFT"
  | "STRONG_COPYLEFT"
  | "NETWORK_COPYLEFT"
  | "UNKNOWN";

export interface LicenseFinding {
  id: string;
  packageName: string;
  version: string;
  ecosystem: Ecosystem;
  spdxId: string;
  category: LicenseCategory;
  severity: Severity;
  isRestrictive: boolean;
  notes: string;
  sourceFile: string;
}

export interface RiskScoringWeights {
  vulnerabilities: number; // default 0.40
  supplyChainAndTyposquat: number; // default 0.20
  secrets: number; // default 0.15
  cicd: number; // default 0.15
  licenseAndConfusion: number; // default 0.10
}

export interface CategoryRiskScore {
  category: string;
  rawPoints: number;
  normalizedScore: number; // 0-100
  weight: number;
  weightedContribution: number;
  maxPossibleContribution: number;
  rationale: string[];
}

export interface RemediationItem {
  id: string;
  priority: 1 | 2 | 3 | 4;
  category:
    | "VULNERABILITY"
    | "MALICIOUS_INDICATOR"
    | "DEPENDENCY_CONFUSION"
    | "CICD"
    | "SECRET"
    | "LICENSE";
  severity: Severity;
  title: string;
  affectedTarget: string;
  actionCommand?: string;
  impactScoreReduction: number;
  description: string;
}

export interface RiskScoreBreakdown {
  overallScore: number; // 0-100 normalized
  postureGrade: "A" | "B" | "C" | "D" | "F";
  postureLabel: "Minimal Risk" | "Low Risk" | "Moderate Risk" | "High Risk" | "Critical Exposure";
  deduplicatedVulnerabilityCount: number;
  categoryScores: CategoryRiskScore[];
  mostExposedDependencies: {
    packageName: string;
    version: string;
    ecosystem: Ecosystem;
    exposureScore: number;
    reasons: string[];
  }[];
  prioritizedRemediations: RemediationItem[];
  methodologySummary: string;
}

export interface ScanStageLog {
  stage: string;
  status: "completed" | "skipped" | "warning" | "error";
  durationMs: number;
  detail: string;
}

export interface ScanReport {
  id: string;
  projectName: string;
  sourceType: "github" | "upload" | "sbom" | "demo";
  repositoryUrl?: string;
  scannedAt: string;
  durationMs: number;
  isDemoData: boolean;
  ecosystems: Ecosystem[];
  scannedFiles: string[];
  unsupportedFiles: { fileName: string; reason: string }[];
  intelligenceStatus: {
    osvLiveQueried: boolean;
    osvPackagesQueried: number;
    registryMetadataLive: boolean;
    notes: string[];
  };
  dependencies: DependencyNode[];
  edges: DependencyEdge[];
  vulnerabilities: VulnerabilityFinding[];
  suspiciousPackages: SuspiciousPackageFinding[];
  dependencyConfusion: DependencyConfusionFinding[];
  cicdFindings: CiCdFinding[];
  secretFindings: SecretFinding[];
  licenseFindings: LicenseFinding[];
  riskScore: RiskScoreBreakdown;
  stageLogs: ScanStageLog[];
}
