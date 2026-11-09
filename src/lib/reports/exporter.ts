import { ScanReport } from "@/types/security";
import { LICENSE_LEGAL_DISCLAIMER } from "@/lib/scanners/licenses";

export interface CycloneDxSbomDocument {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: {
      vendor: string;
      name: string;
      version: string;
    }[];
    component: {
      type: "application";
      name: string;
      "bom-ref": string;
    };
  };
  components: {
    type: "library";
    "bom-ref": string;
    name: string;
    version: string;
    purl: string;
    scope: "required" | "optional";
    licenses?: { license: { id?: string; name?: string } }[];
  }[];
  dependencies: {
    ref: string;
    dependsOn: string[];
  }[];
  vulnerabilities: {
    id: string;
    source: { name: string };
    ratings: {
      severity: string;
      score?: number;
      method?: string;
    }[];
    description: string;
    recommendation: string;
    affects: { ref: string }[];
  }[];
}

function buildPurl(ecosystem: string, name: string, version: string): string {
  switch (ecosystem) {
    case "npm":
      return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
    case "PyPI":
      return `pkg:pypi/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
    case "RubyGems":
      return `pkg:gem/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
    case "Maven": {
      const [group, artifact] = name.split(":");
      return `pkg:maven/${encodeURIComponent(group ?? "unknown")}/${encodeURIComponent(
        artifact ?? name
      )}@${encodeURIComponent(version)}`;
    }
    default:
      return `pkg:generic/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
  }
}

/**
 * Generates a standards-compliant CycloneDX 1.5 SBOM + VDR (Vulnerability Disclosure Report) JSON object.
 */
export function generateCycloneDxSbom(report: ScanReport): CycloneDxSbomDocument {
  const components = report.dependencies.map((dep) => {
    const purl = buildPurl(dep.ecosystem, dep.name, dep.version);
    return {
      type: "library" as const,
      "bom-ref": dep.id,
      name: dep.name,
      version: dep.version,
      purl,
      scope: dep.scope === "direct" ? ("required" as const) : ("optional" as const),
      licenses:
        dep.license && dep.license !== "UNKNOWN"
          ? [{ license: { id: dep.license } }]
          : undefined,
    };
  });

  const dependencies = [
    {
      ref: "root",
      dependsOn: report.dependencies
        .filter((d) => d.scope === "direct")
        .map((d) => d.id),
    },
    ...report.dependencies.map((dep) => ({
      ref: dep.id,
      dependsOn: dep.children,
    })),
  ];

  const vulnerabilities = report.vulnerabilities.map((v) => ({
    id: v.cveId ?? v.id,
    source: { name: v.source },
    ratings: [
      {
        severity: v.severity.toLowerCase(),
        score: v.cvssScore ?? undefined,
        method: v.cvssVector ? "CVSSv31" : undefined,
      },
    ],
    description: v.description,
    recommendation: v.remediation,
    affects: [
      {
        ref: `${v.ecosystem}:${v.packageName}@${v.installedVersion}`,
      },
    ],
  }));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:supplyguard-${report.id.toLowerCase()}`,
    version: 1,
    metadata: {
      timestamp: report.scannedAt,
      tools: [
        {
          vendor: "SupplyGuard Security",
          name: "SupplyGuard SCA & Supply Chain Intelligence Engine",
          version: "1.0.0",
        },
      ],
      component: {
        type: "application",
        name: report.projectName,
        "bom-ref": "root",
      },
    },
    components,
    dependencies,
    vulnerabilities,
  };
}

/**
 * Generates a structured JSON security assessment export including all 12 required sections.
 */
export function generateStructuredReportJson(report: ScanReport): string {
  const payload = {
    reportHeader: {
      platform: "SupplyGuard — Software Supply Chain Security & Intelligence Platform",
      reportId: report.id,
      generatedAt: new Date().toISOString(),
      scanTimestamp: report.scannedAt,
      projectName: report.projectName,
      sourceType: report.sourceType,
      repositoryUrl: report.repositoryUrl ?? "Local Manifest Upload",
      isSampleBenchmarkData: report.isDemoData,
    },
    scanningScope: {
      ecosystemsAnalyzed: report.ecosystems,
      scannedFiles: report.scannedFiles,
      unsupportedFiles: report.unsupportedFiles,
      totalDependencies: report.dependencies.length,
      directDependencies: report.dependencies.filter((d) => d.scope === "direct")
        .length,
      transitiveDependencies: report.dependencies.filter(
        (d) => d.scope === "transitive"
      ).length,
    },
    riskScoreSummary: report.riskScore,
    vulnerabilityFindings: report.vulnerabilities,
    suspiciousPackageFindings: report.suspiciousPackages,
    dependencyConfusionFindings: report.dependencyConfusion,
    cicdSecurityFindings: report.cicdFindings,
    secretDetectionSummary: {
      note: "All detected secret values are strictly masked to prevent credential leakage.",
      findings: report.secretFindings,
    },
    licenseCompliance: {
      disclaimer: LICENSE_LEGAL_DISCLAIMER,
      findings: report.licenseFindings,
    },
    dependencyInventory: report.dependencies,
    remediationPlan: report.riskScore.prioritizedRemediations,
    limitationsAndDataSources: {
      intelligenceSources: [
        "OSV.dev Open Source Vulnerability Database API",
        "GitHub Advisory Database (GHSA) & NVD CVE Cross-References",
        "SupplyGuard Heuristic Typosquatting, Homograph & Lifecycle Script Engine",
        "SupplyGuard Static CI/CD Pipeline & Entropy Secret Analyzer",
      ],
      intelligenceNotes: report.intelligenceStatus.notes,
      securityLimitations: [
        "Static analysis of manifests, lockfiles, and CI workflows cannot guarantee complete absence of zero-day vulnerabilities or runtime backdoors.",
        "Typosquatting and name-similarity findings represent risk indicators requiring human engineering review, not definitive proof of malicious intent.",
        "Technical license classification is an engineering reference and does not constitute legal counsel.",
      ],
    },
  };

  return JSON.stringify(payload, null, 2);
}

/**
 * Generates and downloads a formatted, multi-section PDF Security Assessment Report in the browser.
 */
export async function downloadPdfSecurityReport(report: ScanReport): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const autoTableModule = await import("jspdf-autotable");
  const autoTable = autoTableModule.default;

  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

  // Header Banner
  doc.setFillColor(14, 16, 21);
  doc.rect(0, 0, 210, 36, "F");

  doc.setTextColor(16, 185, 129);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.text("SUPPLYGUARD // SOFTWARE SUPPLY CHAIN SECURITY ASSESSMENT", 14, 13);

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(16);
  doc.text(report.projectName.slice(0, 58), 14, 22);

  doc.setTextColor(160, 170, 185);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.text(
    `Report ID: ${report.id}   |   Scanned: ${new Date(
      report.scannedAt
    ).toUTCString()}   |   Mode: ${
      report.isDemoData ? "SAMPLE BENCHMARK" : report.sourceType.toUpperCase()
    }`,
    14,
    30
  );

  let y = 44;

  // 1. Executive Risk Summary
  doc.setTextColor(20, 24, 33);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("1. Executive Security Posture & Scope", 14, y);
  y += 4;

  autoTable(doc, {
    startY: y,
    head: [
      [
        "Composite Risk Score",
        "Posture Grade",
        "Total Dependencies",
        "Vulnerabilities",
        "Suspicious Pkgs",
        "CI/CD & Secrets",
      ],
    ],
    body: [
      [
        `${report.riskScore.overallScore} / 100 (${report.riskScore.postureLabel})`,
        `Grade ${report.riskScore.postureGrade}`,
        `${report.dependencies.length} (${
          report.dependencies.filter((d) => d.scope === "direct").length
        } direct)`,
        `${report.vulnerabilities.length} advisories`,
        `${report.suspiciousPackages.length} indicators`,
        `${report.cicdFindings.length} CI/CD / ${report.secretFindings.length} Secrets`,
      ],
    ],
    theme: "grid",
    headStyles: { fillColor: [18, 22, 31], textColor: [255, 255, 255], fontSize: 8.5 },
    bodyStyles: { fontSize: 8.5, fontStyle: "bold" },
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  y = (doc as any).lastAutoTable.finalY + 8;

  // 2. Category Risk Breakdown
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text("2. Explainable Risk Score Breakdown by Security Domain", 14, y);
  y += 3;

  autoTable(doc, {
    startY: y,
    head: [["Security Domain", "Normalized Score", "Weight", "Weighted Impact", "Assessment Rationale"]],
    body: report.riskScore.categoryScores.map((c) => [
      c.category,
      `${c.normalizedScore}/100`,
      `${Math.round(c.weight * 100)}%`,
      `${c.weightedContribution} pts`,
      c.rationale.join(" "),
    ]),
    theme: "striped",
    headStyles: { fillColor: [24, 28, 37], fontSize: 8 },
    bodyStyles: { fontSize: 7.5 },
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  y = (doc as any).lastAutoTable.finalY + 8;

  // 3. Vulnerability Findings
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text(`3. Vulnerability Intelligence Findings (${report.vulnerabilities.length})`, 14, y);
  y += 3;

  if (report.vulnerabilities.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Identifier", "Package", "Installed", "Patched", "Scope", "Remediation"]],
      body: report.vulnerabilities.map((v) => [
        v.severity,
        v.cveId ?? v.id,
        `${v.packageName} (${v.ecosystem})`,
        v.installedVersion,
        v.fixedVersion ?? "Unpatched",
        v.dependencyScope,
        v.remediation,
      ]),
      theme: "grid",
      headStyles: { fillColor: [153, 27, 27], fontSize: 8 },
      bodyStyles: { fontSize: 7.5 },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    y = (doc as any).lastAutoTable.finalY + 8;
  } else {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.text("No known vulnerabilities matched in scanned dependency versions.", 14, y + 4);
    y += 10;
  }

  // 4. Supply Chain, Typosquatting & Dependency Confusion
  if (y > 235) {
    doc.addPage();
    y = 18;
  }
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text(
    `4. Suspicious Package & Dependency Confusion Indicators (${
      report.suspiciousPackages.length + report.dependencyConfusion.length
    })`,
    14,
    y
  );
  y += 3;

  const supplyChainRows = [
    ...report.suspiciousPackages.map((s) => [
      s.severity,
      `${s.packageName}@${s.version}`,
      `Suspicion ${s.suspicionScore}/100`,
      s.indicators.map((i) => i.evidence).join("; "),
      s.remediation,
    ]),
    ...report.dependencyConfusion.map((dc) => [
      dc.severity,
      dc.packageName,
      dc.riskType,
      dc.evidence,
      dc.remediation,
    ]),
  ];

  if (supplyChainRows.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Target Package", "Classification", "Technical Evidence", "Recommended Action"]],
      body: supplyChainRows,
      theme: "grid",
      headStyles: { fillColor: [180, 83, 9], fontSize: 8 },
      bodyStyles: { fontSize: 7.5 },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    y = (doc as any).lastAutoTable.finalY + 8;
  } else {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.text("No typosquatting or namespace confusion indicators identified.", 14, y + 4);
    y += 10;
  }

  // 5. CI/CD Workflow & Masked Secret Findings
  if (y > 230) {
    doc.addPage();
    y = 18;
  }
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.text(
    `5. CI/CD Pipeline & Static Secret Findings (${
      report.cicdFindings.length + report.secretFindings.length
    })`,
    14,
    y
  );
  y += 3;

  const cicdAndSecretRows = [
    ...report.cicdFindings.map((c) => [
      c.severity,
      `CI/CD (${c.platform})`,
      `${c.filePath}:${c.lineNumber}`,
      c.title,
      c.remediation,
    ]),
    ...report.secretFindings.map((sec) => [
      sec.severity,
      `Secret (${sec.secretType})`,
      `${sec.filePath}:${sec.lineNumber}`,
      `Masked: ${sec.maskedValue} (Entropy ${sec.entropy})`,
      sec.remediation,
    ]),
  ];

  if (cicdAndSecretRows.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Category", "Location", "Finding / Masked Evidence", "Remediation"]],
      body: cicdAndSecretRows,
      theme: "grid",
      headStyles: { fillColor: [30, 41, 59], fontSize: 8 },
      bodyStyles: { fontSize: 7.5 },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    y = (doc as any).lastAutoTable.finalY + 8;
  } else {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.text("No CI/CD misconfigurations or exposed secrets detected.", 14, y + 4);
    y += 10;
  }

  // 6. Limitations & Disclaimers
  if (y > 245) {
    doc.addPage();
    y = 18;
  }
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9.5);
  doc.text("6. Methodology, Intelligence Sources & Limitations", 14, y);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7.5);
  doc.setTextColor(80, 90, 105);
  const disclaimerLines = doc.splitTextToSize(
    `${report.riskScore.methodologySummary} ${LICENSE_LEGAL_DISCLAIMER}`,
    182
  );
  doc.text(disclaimerLines, 14, y + 5);

  doc.save(`supplyguard-report-${report.id.toLowerCase()}.pdf`);
}
