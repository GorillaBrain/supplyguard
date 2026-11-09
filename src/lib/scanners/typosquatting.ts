import {
  DependencyNode,
  Ecosystem,
  Severity,
  SuspiciousIndicator,
  SuspiciousPackageFinding,
} from "@/types/security";

const POPULAR_PACKAGES: Record<Ecosystem, string[]> = {
  npm: [
    "react",
    "react-dom",
    "next",
    "express",
    "lodash",
    "axios",
    "chalk",
    "commander",
    "dotenv",
    "moment",
    "uuid",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "jsonwebtoken",
    "bcrypt",
    "mongoose",
    "socket.io",
    "underscore",
    "request",
    "cross-env",
    "Node-ipc",
    "colors",
    "faker",
    "minimist",
    "semver",
    "ws",
    "pg",
    "redis",
  ],
  PyPI: [
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "scipy",
    "boto3",
    "botocore",
    "flask",
    "django",
    "fastapi",
    "pydantic",
    "sqlalchemy",
    "cryptography",
    "pyyaml",
    "pillow",
    "matplotlib",
    "scikit-learn",
    "pytest",
    "beautifulsoup4",
    "colorama",
    "paramiko",
  ],
  RubyGems: [
    "rails",
    "rake",
    "bundler",
    "nokogiri",
    "puma",
    "rspec",
    "devise",
    "sidekiq",
    "faraday",
    "activerecord",
    "sinatra",
  ],
  Maven: [
    "org.springframework:spring-core",
    "org.springframework:spring-webmvc",
    "org.apache.logging.log4j:log4j-core",
    "com.fasterxml.jackson.core:jackson-databind",
    "com.google.guava:guava",
    "org.apache.commons:commons-lang3",
    "junit:junit",
  ],
  SBOM: [],
};

/**
 * Computes Damerau-Levenshtein distance between two strings (accounts for adjacent transpositions).
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  const s1 = a.toLowerCase();
  const s2 = b.toLowerCase();
  const len1 = s1.length;
  const len2 = s2.length;

  const dp: number[][] = Array.from({ length: len1 + 1 }, () =>
    Array(len2 + 1).fill(0)
  );

  for (let i = 0; i <= len1; i++) dp[i][0] = i;
  for (let j = 0; j <= len2; j++) dp[0][j] = j;

  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1, // deletion
        dp[i][j - 1] + 1, // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
      if (
        i > 1 &&
        j > 1 &&
        s1[i - 1] === s2[j - 2] &&
        s1[i - 2] === s2[j - 1]
      ) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost); // transposition
      }
    }
  }

  return dp[len1][len2];
}

/**
 * Generates a phonetic / homoglyph skeleton to detect visual or phonetic lookalikes
 * (e.g. `1odash` -> `lodash`, `reqeusts` -> `requests`, `crossenv` -> `cross-env`).
 */
export function normalizeSkeleton(name: string): string {
  return name
    .toLowerCase()
    .replace(/[-_.]/g, "")
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/(.)\1+/g, "$1");
}

/**
 * Detects non-ASCII or Unicode homograph characters in package identifiers.
 */
export function hasUnicodeHomographs(name: string): boolean {
  return /[^\x20-\x7E]/.test(name);
}

const SUSPICIOUS_SCRIPT_PATTERNS: {
  pattern: RegExp;
  label: string;
  weight: number;
}[] = [
  {
    pattern: /\b(?:curl|wget|Invoke-WebRequest)\b.*\|\s*(?:sh|bash|zsh|node|python|pwsh)/i,
    label: "Remote shell pipe execution in lifecycle script",
    weight: 55,
  },
  {
    pattern: /\b(?:curl|wget)\s+https?:\/\/[^\s]+/i,
    label: "Outbound network transfer during package installation",
    weight: 35,
  },
  {
    pattern: /\beval\s*\(|Function\s*\(|Buffer\.from\([^)]+,\s*['"]base64['"]\)/i,
    label: "Obfuscated base64 decoding or dynamic eval() in install hook",
    weight: 45,
  },
  {
    pattern: /\/dev\/tcp\/|\bnc\s+-e|\bnetcat\b|\bwhoami\b|\benv\b.*https?:\/\//i,
    label: "Environment exfiltration or reverse shell indicator in script",
    weight: 60,
  },
];

/**
 * Analyzes dependencies for typosquatting, homographs, anomalous versions, and suspicious lifecycle scripts.
 */
export function detectSuspiciousPackages(
  dependencies: DependencyNode[]
): SuspiciousPackageFinding[] {
  const findings: SuspiciousPackageFinding[] = [];

  for (const dep of dependencies) {
    const indicators: SuspiciousIndicator[] = [];
    let similarPkg: string | undefined;
    let bestDistance: number | undefined;

    const bareName = dep.name.startsWith("@")
      ? dep.name.split("/")[1] ?? dep.name
      : dep.name;
    const candidates = POPULAR_PACKAGES[dep.ecosystem] ?? POPULAR_PACKAGES.npm;

    // 1. Check exact match against popular legitimate packages
    const isExactPopular = candidates.some(
      (c) => c.toLowerCase() === dep.name.toLowerCase()
    );

    // 2. Check Unicode homographs
    if (hasUnicodeHomographs(dep.name)) {
      indicators.push({
        type: "UNICODE_HOMOGRAPH",
        description:
          "Package name contains non-ASCII Unicode characters that may visually impersonate standard ASCII characters.",
        evidence: `Identifier '${dep.name}' contains non-ASCII code points.`,
        weight: 50,
      });
    }

    // 3. Check Levenshtein & Phonetic/Skeleton similarity if not an exact known popular package
    if (!isExactPopular && bareName.length >= 4) {
      for (const target of candidates) {
        const targetLower = target.toLowerCase();
        const depLower = dep.name.toLowerCase();
        if (depLower === targetLower) continue;

        const dist = calculateLevenshteinDistance(depLower, targetLower);
        const skelDep = normalizeSkeleton(depLower);
        const skelTarget = normalizeSkeleton(targetLower);

        if (dist === 1 || (dist === 2 && targetLower.length >= 7)) {
          similarPkg = target;
          bestDistance = dist;
          indicators.push({
            type: "TYPOSQUATTING_LEVENSHTEIN",
            description: `Package name '${dep.name}' has an edit distance of ${dist} from popular ${dep.ecosystem} package '${target}'.`,
            evidence: `Levenshtein/Damerau distance = ${dist} ('${dep.name}' vs '${target}')`,
            weight: dist === 1 ? 38 : 25,
          });
          break;
        } else if (skelDep === skelTarget && depLower !== targetLower) {
          similarPkg = target;
          bestDistance = dist;
          indicators.push({
            type: "PHONETIC_SIMILARITY",
            description: `Package name '${dep.name}' shares an identical homoglyph/phonetic skeleton with '${target}' (hyphen/character substitution).`,
            evidence: `Normalized skeleton '${skelDep}' matches '${target}'`,
            weight: 35,
          });
          break;
        }
      }
    }

    // 4. Check deceptive affix naming conventions around popular libraries
    if (!isExactPopular && !similarPkg) {
      for (const target of candidates) {
        const t = target.toLowerCase();
        const d = bareName.toLowerCase();
        if (
          d === `${t}-js` ||
          d === `${t}-node` ||
          d === `node-${t}` ||
          d === `python-${t}` ||
          d === `${t}-cli-helper` ||
          d === `${t}-utils-core`
        ) {
          similarPkg = target;
          indicators.push({
            type: "SUSPICIOUS_NAMING_CONVENTION",
            description: `Package '${dep.name}' appends a common ecosystem affix to popular package '${target}', a pattern frequently observed in comb-squatting.`,
            evidence: `Affix comb-squatting pattern around '${target}'`,
            weight: 28,
          });
          break;
        }
      }
    }

    // 5. Check suspicious version anomalies (e.g., 99.x.x used in dependency confusion / malicious takeovers)
    const majorMatch = dep.version.match(/^(\d+)\./);
    if (majorMatch) {
      const major = parseInt(majorMatch[1], 10);
      if (major >= 80) {
        indicators.push({
          type: "UNUSUAL_VERSION_ANOMALY",
          description: `Unusually high major version (${dep.version}) often used to force package managers to prefer a shadow package over internal versions.`,
          evidence: `Version '${dep.version}' has major epoch ${major} >= 80`,
          weight: 32,
        });
      }
    }
    if (/0\.0\.1-security/i.test(dep.version)) {
      indicators.push({
        type: "METADATA_ANOMALY",
        description:
          "Version '0.0.1-security' indicates an npm security holding package after a malicious package takedown.",
        evidence: `Installed version is '${dep.version}'`,
        weight: 65,
      });
    }

    // 6. Inspect install script telemetry if available
    if (dep.installScriptContent) {
      for (const rule of SUSPICIOUS_SCRIPT_PATTERNS) {
        if (rule.pattern.test(dep.installScriptContent)) {
          indicators.push({
            type:
              rule.weight >= 40
                ? "SUSPICIOUS_INSTALL_SCRIPT"
                : "EXTERNAL_NETWORK_CALL",
            description: rule.label,
            evidence: `Script snippet: "${dep.installScriptContent.slice(0, 120)}"`,
            weight: rule.weight,
          });
        }
      }
    } else if (dep.hasInstallScripts && similarPkg) {
      indicators.push({
        type: "SUSPICIOUS_INSTALL_SCRIPT",
        description:
          "Package exhibits name similarity to a popular library and declares preinstall/postinstall execution hooks.",
        evidence: `hasInstallScripts=true on lookalike package '${dep.name}'`,
        weight: 25,
      });
    }

    if (indicators.length === 0) continue;

    const rawScore = indicators.reduce((sum, ind) => sum + ind.weight, 0);
    const suspicionScore = Math.min(100, rawScore);

    let severity: Severity = "LOW";
    let classification: SuspiciousPackageFinding["classification"] =
      "LOW_SIMILARITY_INDICATOR";

    if (suspicionScore >= 70) {
      severity = "CRITICAL";
      classification = "HIGH_RISK_INDICATORS";
    } else if (suspicionScore >= 50) {
      severity = "HIGH";
      classification = "HIGH_RISK_INDICATORS";
    } else if (suspicionScore >= 32) {
      severity = "MEDIUM";
      classification = "MODERATE_ANOMALY";
    }

    findings.push({
      id: `SUSP-${dep.ecosystem}-${dep.name}-${dep.version}`,
      packageName: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      suspicionScore,
      severity,
      classification,
      similarLegitimatePackage: similarPkg,
      editDistance: bestDistance,
      indicators,
      sourceFile: dep.sourceFile,
      remediation: similarPkg
        ? `Verify whether '${dep.name}' was intended or is a typo for '${similarPkg}'. Inspect package provenance before running install scripts (use --ignore-scripts during investigation).`
        : `Audit the package contents and lifecycle scripts of '${dep.name}@${dep.version}' before executing builds in privileged environments.`,
    });
  }

  return findings.sort((a, b) => b.suspicionScore - a.suspicionScore);
}
