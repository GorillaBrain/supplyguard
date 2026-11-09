import {
  DependencyNode,
  LicenseCategory,
  LicenseFinding,
  Severity,
} from "@/types/security";

export const LICENSE_LEGAL_DISCLAIMER =
  "Technical License Identification Disclaimer: SupplyGuard extracts license metadata from package manifests, lockfiles, and registry descriptors. This analysis is an engineering aid and does not constitute legal advice. Consult qualified legal counsel regarding open-source distribution obligations.";

const KNOWN_PACKAGE_LICENSES: Record<string, string> = {
  react: "MIT",
  "react-dom": "MIT",
  next: "MIT",
  lodash: "MIT",
  axios: "MIT",
  express: "MIT",
  minimist: "MIT",
  jsonwebtoken: "MIT",
  chalk: "MIT",
  commander: "MIT",
  dotenv: "BSD-2-Clause",
  semver: "ISC",
  typescript: "Apache-2.0",
  webpack: "MIT",
  eslint: "MIT",
  uuid: "MIT",
  ws: "MIT",
  pg: "MIT",
  requests: "Apache-2.0",
  urllib3: "MIT",
  pyyaml: "MIT",
  flask: "BSD-3-Clause",
  django: "BSD-3-Clause",
  fastapi: "MIT",
  numpy: "BSD-3-Clause",
  pandas: "BSD-3-Clause",
  cryptography: "Apache-2.0",
  boto3: "Apache-2.0",
  rails: "MIT",
  nokogiri: "MIT",
  puma: "BSD-3-Clause",
  "org.apache.logging.log4j:log4j-core": "Apache-2.0",
  "org.springframework:spring-webmvc": "Apache-2.0",
  "com.fasterxml.jackson.core:jackson-databind": "Apache-2.0",
  "mysql-connector-python": "GPL-2.0-only",
  "chardet": "LGPL-2.1-only",
  "readline": "GPL-3.0-only",
  "agpl-logger": "AGPL-3.0-only",
  "pdfjs-dist": "Apache-2.0",
};

export function classifyLicenseSpdx(rawLicense?: string): {
  spdxId: string;
  category: LicenseCategory;
  severity: Severity;
  isRestrictive: boolean;
  notes: string;
} {
  if (!rawLicense || !rawLicense.trim()) {
    return {
      spdxId: "UNKNOWN",
      category: "UNKNOWN",
      severity: "LOW",
      isRestrictive: false,
      notes:
        "No explicit SPDX license identifier found in lockfile or manifest metadata. Verify upstream repository LICENSE file before redistribution.",
    };
  }

  const normalized = rawLicense.trim().toUpperCase();

  if (normalized.includes("AGPL")) {
    return {
      spdxId: "AGPL-3.0",
      category: "NETWORK_COPYLEFT",
      severity: "HIGH",
      isRestrictive: true,
      notes:
        "Network copyleft license (AGPL). Interacting with modified software over a network may trigger source disclosure obligations depending on deployment architecture.",
    };
  }

  if (
    normalized.includes("LGPL") ||
    normalized.includes("LESSER GENERAL PUBLIC")
  ) {
    return {
      spdxId: normalized.includes("3") ? "LGPL-3.0" : "LGPL-2.1",
      category: "WEAK_COPYLEFT",
      severity: "MEDIUM",
      isRestrictive: true,
      notes:
        "Weak copyleft license (LGPL). Dynamic linking is typically permitted, but direct modification or static bundling may require relinking provisions.",
    };
  }

  if (normalized.includes("GPL")) {
    return {
      spdxId: normalized.includes("2") ? "GPL-2.0" : "GPL-3.0",
      category: "STRONG_COPYLEFT",
      severity: "HIGH",
      isRestrictive: true,
      notes:
        "Strong copyleft license (GPL). Distributing linked binary or bundled derivative works may require licensing the combined work under compatible terms.",
    };
  }

  if (normalized.includes("MPL")) {
    return {
      spdxId: "MPL-2.0",
      category: "WEAK_COPYLEFT",
      severity: "LOW",
      isRestrictive: true,
      notes:
        "File-level weak copyleft license (Mozilla Public License 2.0). Modifications to MPL-licensed files must remain under MPL, while larger works may be combined.",
    };
  }

  if (normalized.includes("APACHE")) {
    return {
      spdxId: "Apache-2.0",
      category: "PERMISSIVE",
      severity: "INFO",
      isRestrictive: false,
      notes:
        "Permissive open-source license with an express patent grant. Requires preservation of copyright and NOTICE attributions.",
    };
  }

  if (normalized.includes("BSD-3") || normalized === "BSD") {
    return {
      spdxId: "BSD-3-Clause",
      category: "PERMISSIVE",
      severity: "INFO",
      isRestrictive: false,
      notes:
        "Permissive BSD 3-Clause license. Permits commercial and proprietary distribution with copyright notice retention.",
    };
  }

  if (normalized.includes("BSD-2") || normalized.includes("SIMPLIFIED BSD")) {
    return {
      spdxId: "BSD-2-Clause",
      category: "PERMISSIVE",
      severity: "INFO",
      isRestrictive: false,
      notes:
        "Permissive BSD 2-Clause license. Permits redistribution in source or binary form with attribution.",
    };
  }

  if (normalized.includes("ISC")) {
    return {
      spdxId: "ISC",
      category: "PERMISSIVE",
      severity: "INFO",
      isRestrictive: false,
      notes:
        "Permissive ISC license functionally equivalent to simplified BSD and MIT.",
    };
  }

  if (normalized.includes("MIT") || normalized.includes("0BSD") || normalized.includes("UNLICENSE")) {
    return {
      spdxId: "MIT",
      category: "PERMISSIVE",
      severity: "INFO",
      isRestrictive: false,
      notes:
        "Permissive MIT license allowing commercial use, modification, and distribution with copyright notice preservation.",
    };
  }

  return {
    spdxId: rawLicense.trim(),
    category: "UNKNOWN",
    severity: "LOW",
    isRestrictive: false,
    notes: `Non-standard or custom license expression ('${rawLicense.trim()}'). Review license terms manually.`,
  };
}

export function analyzeLicenses(
  dependencies: DependencyNode[]
): LicenseFinding[] {
  return dependencies.map((dep) => {
    const inferredLicense =
      dep.license ?? KNOWN_PACKAGE_LICENSES[dep.name.toLowerCase()];
    const classified = classifyLicenseSpdx(inferredLicense);

    if (!dep.license && inferredLicense) {
      dep.license = classified.spdxId;
    }

    return {
      id: `LIC-${dep.ecosystem}-${dep.name}-${dep.version}`,
      packageName: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      spdxId: classified.spdxId,
      category: classified.category,
      severity: classified.severity,
      isRestrictive: classified.isRestrictive,
      notes: classified.notes,
      sourceFile: dep.sourceFile,
    };
  });
}
