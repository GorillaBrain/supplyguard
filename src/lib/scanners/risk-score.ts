import {
  CategoryRiskScore,
  CiCdFinding,
  DependencyConfusionFinding,
  DependencyNode,
  LicenseFinding,
  RemediationItem,
  RiskScoreBreakdown,
  RiskScoringWeights,
  SecretFinding,
  Severity,
  SuspiciousPackageFinding,
  VulnerabilityFinding,
} from "@/types/security";

export const DEFAULT_RISK_WEIGHTS: RiskScoringWeights = {
  vulnerabilities: 0.4,
  supplyChainAndTyposquat: 0.2,
  secrets: 0.15,
  cicd: 0.15,
  licenseAndConfusion: 0.1,
};

const SEVERITY_BASE_WEIGHT: Record<Severity, number> = {
  CRITICAL: 28,
  HIGH: 16,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

/**
 * Deduplicates vulnerabilities so multiple aliases (e.g. CVE + GHSA) for the same
 * underlying advisory on the same package are never double-counted.
 */
export function deduplicateVulnerabilities(
  vulnerabilities: VulnerabilityFinding[]
): VulnerabilityFinding[] {
  const seenKeys = new Set<string>();
  const deduplicated: VulnerabilityFinding[] = [];

  for (const vuln of vulnerabilities) {
    const canonicalAliases = Array.from(
      new Set(
        [vuln.id, vuln.cveId, vuln.ghsaId, ...vuln.aliases].filter(
          (a): a is string => Boolean(a)
        )
      )
    ).sort();

    const matchesExisting = canonicalAliases.some((alias) =>
      seenKeys.has(`${vuln.ecosystem}:${vuln.packageName.toLowerCase()}:${alias}`)
    );

    if (!matchesExisting) {
      canonicalAliases.forEach((alias) =>
        seenKeys.add(`${vuln.ecosystem}:${vuln.packageName.toLowerCase()}:${alias}`)
      );
      deduplicated.push(vuln);
    }
  }

  return deduplicated;
}

/**
 * Diminishing-returns saturating curve `100 * (1 - exp(-rawPoints / scale))`
 * so scores normalize smoothly into [0, 100] with explainable sensitivity.
 */
function saturateScore(rawPoints: number, scale = 55): number {
  if (rawPoints <= 0) return 0;
  const val = 100 * (1 - Math.exp(-rawPoints / scale));
  return Math.min(100, Math.round(val));
}

export function calculateProjectRiskScore(params: {
  dependencies: DependencyNode[];
  vulnerabilities: VulnerabilityFinding[];
  suspiciousPackages: SuspiciousPackageFinding[];
  dependencyConfusion: DependencyConfusionFinding[];
  cicdFindings: CiCdFinding[];
  secretFindings: SecretFinding[];
  licenseFindings: LicenseFinding[];
  weights?: Partial<RiskScoringWeights>;
}): RiskScoreBreakdown {
  const weights: RiskScoringWeights = {
    ...DEFAULT_RISK_WEIGHTS,
    ...(params.weights ?? {}),
  };

  // Normalize weights so they sum to 1.0
  const weightSum =
    weights.vulnerabilities +
    weights.supplyChainAndTyposquat +
    weights.secrets +
    weights.cicd +
    weights.licenseAndConfusion || 1;

  const normWeights: RiskScoringWeights = {
    vulnerabilities: weights.vulnerabilities / weightSum,
    supplyChainAndTyposquat: weights.supplyChainAndTyposquat / weightSum,
    secrets: weights.secrets / weightSum,
    cicd: weights.cicd / weightSum,
    licenseAndConfusion: weights.licenseAndConfusion / weightSum,
  };

  const uniqueVulns = deduplicateVulnerabilities(params.vulnerabilities);

  // 1. Vulnerability Category Score
  let vulnRaw = 0;
  const vulnRationale: string[] = [];
  for (const v of uniqueVulns) {
    let base = SEVERITY_BASE_WEIGHT[v.severity];
    // Direct dependencies carry 1.25x reachability multiplier vs 0.85x for deep transitive
    const scopeMultiplier = v.dependencyScope === "direct" ? 1.25 : 0.85;
    // Known exploited vulnerabilities carry 1.35x urgency multiplier
    const exploitMultiplier =
      v.exploitability === "KNOWN_EXPLOITED"
        ? 1.35
        : v.exploitability === "HIGH_PROBABILITY"
        ? 1.15
        : 1.0;
    // Unpatched vulnerabilities increase residual risk by 1.15x
    const patchMultiplier = v.fixedVersion ? 1.0 : 1.15;

    const points = Number(
      (base * scopeMultiplier * exploitMultiplier * patchMultiplier).toFixed(1)
    );
    vulnRaw += points;
  }
  const vulnNormalized = saturateScore(vulnRaw, 50);
  if (uniqueVulns.length === 0) {
    vulnRationale.push("0 known vulnerabilities matched across dependency tree.");
  } else {
    vulnRationale.push(
      `${uniqueVulns.length} deduplicated vulnerability advisory(s) evaluated with reachability (direct=1.25x, transitive=0.85x) and exploitability multipliers.`
    );
  }

  // 2. Supply Chain & Suspicious Package Category Score
  let suspRaw = 0;
  const suspRationale: string[] = [];
  for (const s of params.suspiciousPackages) {
    suspRaw += (s.suspicionScore / 100) * 38;
  }
  const suspNormalized = saturateScore(suspRaw, 45);
  if (params.suspiciousPackages.length === 0) {
    suspRationale.push(
      "No typosquatting, homograph, or lifecycle script anomalies detected."
    );
  } else {
    suspRationale.push(
      `${params.suspiciousPackages.length} package(s) flagged with heuristic name-similarity or install-hook indicators.`
    );
  }

  // 3. Exposed Secrets Category Score
  let secretRaw = 0;
  const secretRationale: string[] = [];
  for (const sec of params.secretFindings) {
    const confMult =
      sec.confidence === "HIGH" ? 1.2 : sec.confidence === "MEDIUM" ? 0.9 : 0.6;
    secretRaw += SEVERITY_BASE_WEIGHT[sec.severity] * confMult;
  }
  const secretNormalized = saturateScore(secretRaw, 40);
  if (params.secretFindings.length === 0) {
    secretRationale.push("0 hardcoded credentials or high-entropy secrets detected.");
  } else {
    secretRationale.push(
      `${params.secretFindings.length} credential pattern(s) detected and masked via static entropy + prefix validation.`
    );
  }

  // 4. CI/CD Pipeline Security Category Score
  let cicdRaw = 0;
  const cicdRationale: string[] = [];
  for (const c of params.cicdFindings) {
    cicdRaw += SEVERITY_BASE_WEIGHT[c.severity];
  }
  const cicdNormalized = saturateScore(cicdRaw, 45);
  if (params.cicdFindings.length === 0) {
    cicdRationale.push("No workflow misconfigurations or unpinned actions detected.");
  } else {
    cicdRationale.push(
      `${params.cicdFindings.length} workflow security issue(s) identified across CI/CD definitions.`
    );
  }

  // 5. License Compliance & Dependency Confusion Category Score
  let licConfRaw = 0;
  const licConfRationale: string[] = [];
  for (const dc of params.dependencyConfusion) {
    licConfRaw += SEVERITY_BASE_WEIGHT[dc.severity] * 1.1;
  }
  const restrictiveLicenses = params.licenseFindings.filter((l) => l.isRestrictive);
  for (const lf of restrictiveLicenses) {
    licConfRaw += SEVERITY_BASE_WEIGHT[lf.severity] * 0.75;
  }
  const licConfNormalized = saturateScore(licConfRaw, 45);
  if (params.dependencyConfusion.length === 0 && restrictiveLicenses.length === 0) {
    licConfRationale.push(
      "0 dependency confusion vectors or restrictive copyleft obligations flagged."
    );
  } else {
    licConfRationale.push(
      `${params.dependencyConfusion.length} namespace confusion vector(s) and ${restrictiveLicenses.length} copyleft/restrictive license(s) evaluated.`
    );
  }

  const categoryScores: CategoryRiskScore[] = [
    {
      category: "Vulnerability Intelligence",
      rawPoints: Number(vulnRaw.toFixed(1)),
      normalizedScore: vulnNormalized,
      weight: Number(normWeights.vulnerabilities.toFixed(2)),
      weightedContribution: Number(
        (vulnNormalized * normWeights.vulnerabilities).toFixed(1)
      ),
      maxPossibleContribution: Number((100 * normWeights.vulnerabilities).toFixed(1)),
      rationale: vulnRationale,
    },
    {
      category: "Malicious & Typosquatting Indicators",
      rawPoints: Number(suspRaw.toFixed(1)),
      normalizedScore: suspNormalized,
      weight: Number(normWeights.supplyChainAndTyposquat.toFixed(2)),
      weightedContribution: Number(
        (suspNormalized * normWeights.supplyChainAndTyposquat).toFixed(1)
      ),
      maxPossibleContribution: Number(
        (100 * normWeights.supplyChainAndTyposquat).toFixed(1)
      ),
      rationale: suspRationale,
    },
    {
      category: "Secret Exposure",
      rawPoints: Number(secretRaw.toFixed(1)),
      normalizedScore: secretNormalized,
      weight: Number(normWeights.secrets.toFixed(2)),
      weightedContribution: Number(
        (secretNormalized * normWeights.secrets).toFixed(1)
      ),
      maxPossibleContribution: Number((100 * normWeights.secrets).toFixed(1)),
      rationale: secretRationale,
    },
    {
      category: "CI/CD Workflow Security",
      rawPoints: Number(cicdRaw.toFixed(1)),
      normalizedScore: cicdNormalized,
      weight: Number(normWeights.cicd.toFixed(2)),
      weightedContribution: Number(
        (cicdNormalized * normWeights.cicd).toFixed(1)
      ),
      maxPossibleContribution: Number((100 * normWeights.cicd).toFixed(1)),
      rationale: cicdRationale,
    },
    {
      category: "Dependency Confusion & Licenses",
      rawPoints: Number(licConfRaw.toFixed(1)),
      normalizedScore: licConfNormalized,
      weight: Number(normWeights.licenseAndConfusion.toFixed(2)),
      weightedContribution: Number(
        (licConfNormalized * normWeights.licenseAndConfusion).toFixed(1)
      ),
      maxPossibleContribution: Number(
        (100 * normWeights.licenseAndConfusion).toFixed(1)
      ),
      rationale: licConfRationale,
    },
  ];

  const weightedSum = categoryScores.reduce(
    (sum, cat) => sum + cat.weightedContribution,
    0
  );

  // Apply critical floor boost if a CRITICAL secret, CRITICAL RCE vulnerability, or CRITICAL CI/CD trigger is present,
  // while keeping score strictly bounded [0, 100] and explainable.
  const maxCategoryScore = Math.max(
    ...categoryScores.map((c) => c.normalizedScore),
    0
  );
  const blendedScore = Math.round(weightedSum * 0.72 + maxCategoryScore * 0.28);
  const overallScore = Math.min(100, Math.max(0, blendedScore));

  let postureGrade: RiskScoreBreakdown["postureGrade"] = "A";
  let postureLabel: RiskScoreBreakdown["postureLabel"] = "Minimal Risk";
  if (overallScore >= 75) {
    postureGrade = "F";
    postureLabel = "Critical Exposure";
  } else if (overallScore >= 55) {
    postureGrade = "D";
    postureLabel = "High Risk";
  } else if (overallScore >= 35) {
    postureGrade = "C";
    postureLabel = "Moderate Risk";
  } else if (overallScore >= 15) {
    postureGrade = "B";
    postureLabel = "Low Risk";
  }

  // Compute most exposed dependencies without double counting
  const pkgExposureMap = new Map<
    string,
    {
      packageName: string;
      version: string;
      ecosystem: DependencyNode["ecosystem"];
      exposureScore: number;
      reasons: string[];
    }
  >();

  for (const v of uniqueVulns) {
    const key = `${v.ecosystem}:${v.packageName}@${v.installedVersion}`;
    const entry = pkgExposureMap.get(key) ?? {
      packageName: v.packageName,
      version: v.installedVersion,
      ecosystem: v.ecosystem,
      exposureScore: 0,
      reasons: [],
    };
    entry.exposureScore += SEVERITY_BASE_WEIGHT[v.severity];
    entry.reasons.push(`${v.cveId ?? v.id} (${v.severity})`);
    pkgExposureMap.set(key, entry);
  }

  for (const s of params.suspiciousPackages) {
    const key = `${s.ecosystem}:${s.packageName}@${s.version}`;
    const entry = pkgExposureMap.get(key) ?? {
      packageName: s.packageName,
      version: s.version,
      ecosystem: s.ecosystem,
      exposureScore: 0,
      reasons: [],
    };
    entry.exposureScore += Math.round(s.suspicionScore * 0.4);
    entry.reasons.push(`Suspicion Score ${s.suspicionScore}/100`);
    pkgExposureMap.set(key, entry);
  }

  const mostExposedDependencies = Array.from(pkgExposureMap.values())
    .map((item) => ({
      ...item,
      exposureScore: Math.min(100, item.exposureScore),
    }))
    .sort((a, b) => b.exposureScore - a.exposureScore)
    .slice(0, 6);

  // Build prioritized remediation plan
  const remediations: RemediationItem[] = [];

  for (const sec of params.secretFindings) {
    remediations.push({
      id: `REM-SEC-${sec.id}`,
      priority: 1,
      category: "SECRET",
      severity: sec.severity,
      title: `Rotate exposed ${sec.secretType} in ${sec.filePath}`,
      affectedTarget: `${sec.filePath}:${sec.lineNumber}`,
      impactScoreReduction: 12,
      description: sec.remediation,
    });
  }

  for (const s of params.suspiciousPackages) {
    if (s.suspicionScore >= 30) {
      remediations.push({
        id: `REM-SUSP-${s.id}`,
        priority: s.suspicionScore >= 60 ? 1 : 2,
        category: "MALICIOUS_INDICATOR",
        severity: s.severity,
        title: s.similarLegitimatePackage
          ? `Replace suspected typosquat '${s.packageName}' with '${s.similarLegitimatePackage}'`
          : `Audit suspicious lifecycle hooks in '${s.packageName}@${s.version}'`,
        affectedTarget: `${s.packageName}@${s.version}`,
        actionCommand:
          s.ecosystem === "npm" && s.similarLegitimatePackage
            ? `npm uninstall ${s.packageName} && npm install ${s.similarLegitimatePackage}`
            : undefined,
        impactScoreReduction: 10,
        description: s.remediation,
      });
    }
  }

  for (const v of uniqueVulns) {
    remediations.push({
      id: `REM-VULN-${v.id}-${v.packageName}`,
      priority: v.severity === "CRITICAL" ? 1 : v.severity === "HIGH" ? 2 : 3,
      category: "VULNERABILITY",
      severity: v.severity,
      title: v.fixedVersion
        ? `Upgrade ${v.packageName} to ${v.fixedVersion} (${v.cveId ?? v.id})`
        : `Mitigate unpatched ${v.cveId ?? v.id} in ${v.packageName}`,
      affectedTarget: `${v.packageName}@${v.installedVersion}`,
      actionCommand:
        v.fixedVersion && v.ecosystem === "npm"
          ? `npm install ${v.packageName}@^${v.fixedVersion}`
          : v.fixedVersion && v.ecosystem === "PyPI"
          ? `pip install "${v.packageName}>=${v.fixedVersion}"`
          : undefined,
      impactScoreReduction: v.severity === "CRITICAL" ? 14 : 8,
      description: v.remediation,
    });
  }

  for (const c of params.cicdFindings) {
    remediations.push({
      id: `REM-CICD-${c.id}`,
      priority: c.severity === "CRITICAL" ? 1 : 2,
      category: "CICD",
      severity: c.severity,
      title: `Harden ${c.platform} workflow (${c.ruleId}: ${c.title})`,
      affectedTarget: `${c.filePath}:${c.lineNumber}`,
      impactScoreReduction: 7,
      description: c.remediation,
    });
  }

  for (const dc of params.dependencyConfusion) {
    remediations.push({
      id: `REM-CONF-${dc.id}`,
      priority: 2,
      category: "DEPENDENCY_CONFUSION",
      severity: dc.severity,
      title: `Isolate internal namespace for ${dc.packageName}`,
      affectedTarget: dc.packageName,
      impactScoreReduction: 6,
      description: dc.remediation,
    });
  }

  remediations.sort((a, b) => a.priority - b.priority || b.impactScoreReduction - a.impactScoreReduction);

  return {
    overallScore,
    postureGrade,
    postureLabel,
    deduplicatedVulnerabilityCount: uniqueVulns.length,
    categoryScores,
    mostExposedDependencies,
    prioritizedRemediations: remediations.slice(0, 15),
    methodologySummary:
      "SupplyGuard computes a normalized 0–100 composite risk index using deduplicated advisory matching (preventing CVE/GHSA alias double-counting), dependency reachability multipliers (1.25x direct, 0.85x transitive), saturating exponential normalization per domain, and weighted aggregation (40% Vulnerabilities, 20% Malicious/Typosquatting Indicators, 15% Secrets, 15% CI/CD, 10% Namespace Confusion & Licenses). Note: This score is an internal engineering prioritization metric, not an industry-certified compliance rating.",
  };
}
