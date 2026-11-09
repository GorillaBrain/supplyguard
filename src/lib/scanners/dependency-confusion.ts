import {
  DependencyConfusionFinding,
  DependencyNode,
  Ecosystem,
} from "@/types/security";

const INTERNAL_NAME_PATTERNS = [
  /^@(?:internal|corp|company|private|enterprise|intranet|staging)\//i,
  /^(?:internal|corp|private|intranet|company)[-_][a-z0-9]/i,
  /[a-z0-9][-_](?:internal|private|corp|proprietary)$/i,
];

/**
 * Analyzes dependencies and registry configurations (.npmrc, pip.conf, requirements.txt)
 * for potential Dependency Confusion exposure.
 */
export function analyzeDependencyConfusion(
  dependencies: DependencyNode[],
  registryConfigs: { filePath: string; ecosystem: Ecosystem; content: string }[],
  rawFiles: { name: string; content: string }[],
  customInternalPrefixes: string[] = []
): DependencyConfusionFinding[] {
  const findings: DependencyConfusionFinding[] = [];

  // Collect scoped registry mappings from .npmrc if present
  const mappedScopes = new Set<string>();
  for (const cfg of registryConfigs) {
    if (cfg.ecosystem === "npm") {
      const lines = cfg.content.split(/\r?\n/);
      for (const line of lines) {
        const scopeMatch = line.trim().match(/^(@[a-z0-9._-]+):registry\s*=\s*(.+)$/i);
        if (scopeMatch) {
          mappedScopes.add(scopeMatch[1].toLowerCase());
        }
      }
      // Check if .npmrc defines a custom registry alongside public fallback without scope locking
      if (
        /registry\s*=\s*https?:\/\/(?!(?:registry\.npmjs\.org|registry\.yarnpkg\.com))/i.test(
          cfg.content
        ) &&
        mappedScopes.size === 0
      ) {
        findings.push({
          id: `CONF-NPMRC-${cfg.filePath}`,
          packageName: ".npmrc (Global Registry Override)",
          version: "N/A",
          ecosystem: "npm",
          severity: "MEDIUM",
          riskType: "MISSING_SCOPE_MAPPING",
          evidence: `File '${cfg.filePath}' configures a non-standard default registry without explicit '@scope:registry=' isolation.`,
          sourceFile: cfg.filePath,
          explanation:
            "Potential exposure: Relying on a global private registry URL without scoping internal packages (@org/pkg) can allow public registry fallback if a developer or CI runner lacks the .npmrc file.",
          remediation:
            "Bind internal packages to a dedicated organization scope (e.g., @company:registry=https://npm.internal.example/) and configure your private registry to block upstream proxy lookups for internal namespaces.",
        });
      }
    }

    if (cfg.ecosystem === "PyPI") {
      if (/extra-index-url/i.test(cfg.content)) {
        findings.push({
          id: `CONF-PIPCONF-${cfg.filePath}`,
          packageName: "pip.conf (extra-index-url)",
          version: "N/A",
          ecosystem: "PyPI",
          severity: "HIGH",
          riskType: "INSECURE_REGISTRY_MIXING",
          evidence: `'extra-index-url' directive detected in '${cfg.filePath}'.`,
          sourceFile: cfg.filePath,
          explanation:
            "Potential exposure: pip evaluates both PyPI and every '--extra-index-url' simultaneously and installs whichever index serves the highest version number, enabling public namespace shadowing.",
          remediation:
            "Replace 'extra-index-url' with '--index-url' pointing exclusively to an internal artifact proxy (e.g., Artifactory, Nexus, AWS CodeArtifact) that enforces namespace routing.",
        });
      }
    }
  }

  // Also check requirements.txt for inline --extra-index-url
  for (const file of rawFiles) {
    if (/requirements.*\.txt$/i.test(file.name) && /--extra-index-url/i.test(file.content)) {
      findings.push({
        id: `CONF-REQ-EXTRA-INDEX-${file.name}`,
        packageName: "requirements.txt (--extra-index-url)",
        version: "N/A",
        ecosystem: "PyPI",
        severity: "HIGH",
        riskType: "INSECURE_REGISTRY_MIXING",
        evidence: `'--extra-index-url' flag present in '${file.name}'.`,
        sourceFile: file.name,
        explanation:
          "Potential exposure: Using '--extra-index-url' causes pip to query both public PyPI and the private index, choosing whichever hosts the higher version number.",
        remediation:
          "Use '--index-url' pointing to a single controlled repository proxy and reserve internal package names on public PyPI if necessary.",
      });
    }
  }

  // Inspect individual packages for internal naming patterns & private resolution hints
  for (const dep of dependencies) {
    const lowerName = dep.name.toLowerCase();
    const matchesBuiltinPattern = INTERNAL_NAME_PATTERNS.some((p) =>
      p.test(lowerName)
    );
    const matchesCustomPrefix = customInternalPrefixes.some(
      (prefix) =>
        prefix.trim() &&
        lowerName.startsWith(prefix.trim().toLowerCase())
    );

    const isPrivateResolvedUrl =
      dep.resolvedUrl &&
      !/registry\.npmjs\.org|registry\.yarnpkg\.com|files\.pythonhosted\.org|rubygems\.org|repo\.maven\.apache\.org/i.test(
        dep.resolvedUrl
      );

    if (matchesBuiltinPattern || matchesCustomPrefix || isPrivateResolvedUrl) {
      const isScoped = dep.name.startsWith("@");
      const scopePrefix = isScoped ? dep.name.split("/")[0].toLowerCase() : null;

      if (!isScoped) {
        findings.push({
          id: `CONF-UNSCOPED-${dep.ecosystem}-${dep.name}`,
          packageName: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          severity: "HIGH",
          riskType: "UNSCOPED_INTERNAL_NAMING",
          evidence: isPrivateResolvedUrl
            ? `Unscoped package '${dep.name}' resolved from non-public URL '${dep.resolvedUrl}'.`
            : `Unscoped package '${dep.name}' matches internal naming indicator (${
                matchesCustomPrefix ? "custom prefix" : "internal/private affix"
              }).`,
          sourceFile: dep.sourceFile,
          explanation:
            "Potential exposure: Unscoped internal package names can be registered by third parties on public registries (npm, PyPI, RubyGems). If a build environment queries the public registry with a higher version number, the public package may be installed.",
          remediation:
            dep.ecosystem === "npm"
              ? `Migrate '${dep.name}' to a verified organization scope (e.g., '@your-org/${dep.name}') and lock scope resolution in .npmrc.`
              : `Configure your package manager to resolve exclusively through an internal artifact proxy with namespace pinning for '${dep.name}'.`,
        });
      } else if (scopePrefix && !mappedScopes.has(scopePrefix)) {
        findings.push({
          id: `CONF-SCOPED-UNMAPPED-${dep.ecosystem}-${dep.name}`,
          packageName: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          severity: "MEDIUM",
          riskType: "PUBLIC_NAMESPACE_COLLISION_RISK",
          evidence: `Scoped internal package '${dep.name}' has no corresponding '${scopePrefix}:registry=' binding in a scanned .npmrc file.`,
          sourceFile: dep.sourceFile,
          explanation:
            "Potential exposure: If the organization scope is not claimed on the public npm registry or explicitly pinned to a private registry via .npmrc, builds without local registry configuration will query public npm.",
          remediation: `Ensure the '${scopePrefix}' organization is claimed on npmjs.com and commit a project-level .npmrc mapping '${scopePrefix}:registry=' to your internal registry.`,
        });
      }
    }
  }

  return findings;
}
