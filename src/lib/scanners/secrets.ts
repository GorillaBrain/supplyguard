import { SecretFinding, Severity } from "@/types/security";

/**
 * Calculates Shannon entropy (bits per character) to distinguish real cryptographic material
 * from human-readable words or low-entropy placeholders.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

/**
 * Strictly masks a detected secret so complete values are NEVER exposed in memory, UI, logs, or reports.
 */
export function maskSecretValue(rawSecret: string): string {
  const cleaned = rawSecret.trim();
  if (cleaned.length <= 8) {
    return `${cleaned.slice(0, 2)}******`;
  }
  const prefix = cleaned.slice(0, 4);
  const suffix = cleaned.slice(-3);
  const maskedLen = Math.min(16, Math.max(8, cleaned.length - 7));
  return `${prefix}${"*".repeat(maskedLen)}${suffix}`;
}

interface SecretPatternRule {
  ruleId: string;
  secretType: SecretFinding["secretType"];
  severity: Severity;
  regex: RegExp;
  minEntropy: number;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  falsePositiveNote: string;
  remediation: string;
}

const SECRET_RULES: SecretPatternRule[] = [
  {
    ruleId: "SEC-AWS-001",
    secretType: "AWS Access Key ID",
    severity: "CRITICAL",
    regex: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/,
    minEntropy: 3.0,
    confidence: "HIGH",
    falsePositiveNote:
      "AWS documentation sometimes includes 'AKIAIOSFODNN7EXAMPLE' as an example key. Verify whether the IAM key is active in AWS IAM.",
    remediation:
      "Immediately deactivate and rotate the AWS Access Key in IAM, audit CloudTrail logs for unauthorized API calls, and migrate to IAM Roles or OIDC federation.",
  },
  {
    ruleId: "SEC-GH-001",
    secretType: "GitHub Personal Access Token",
    severity: "CRITICAL",
    regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/,
    minEntropy: 3.6,
    confidence: "HIGH",
    falsePositiveNote:
      "High-confidence prefix match ('ghp_' / 'github_pat_'). False positives only occur in synthetic test fixtures.",
    remediation:
      "Revoke the token immediately in GitHub Developer Settings, audit organization security logs, and replace with short-lived GitHub App installation tokens.",
  },
  {
    ruleId: "SEC-PK-001",
    secretType: "Private Key Material",
    severity: "CRITICAL",
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/,
    minEntropy: 2.5,
    confidence: "HIGH",
    falsePositiveNote:
      "May be a local development or self-signed test key. Treat any committed private key as compromised until verified.",
    remediation:
      "Revoke the associated public key or certificate, purge the private key from Git history (git filter-repo), and load keys at runtime from a secret manager.",
  },
  {
    ruleId: "SEC-STRIPE-001",
    secretType: "Stripe Live API Key",
    severity: "CRITICAL",
    regex: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b/,
    minEntropy: 3.5,
    confidence: "HIGH",
    falsePositiveNote:
      "Keys prefixed with 'sk_test_' are sandbox keys; 'sk_live_' and 'rk_live_' are production billing credentials.",
    remediation:
      "Roll the live API key in the Stripe Dashboard immediately and restrict key permissions using scoped Restricted Keys.",
  },
  {
    ruleId: "SEC-SLACK-001",
    secretType: "Slack Webhook / Bot Token",
    severity: "HIGH",
    regex: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34})\b/,
    minEntropy: 3.5,
    confidence: "HIGH",
    falsePositiveNote:
      "Matches standard Slack token structure. Confirm whether the workspace app is still installed.",
    remediation:
      "Regenerate the Slack Bot/User token in the Slack API App Management portal and store it in environment secrets.",
  },
  {
    ruleId: "SEC-DB-001",
    secretType: "Database Connection URI",
    severity: "HIGH",
    regex: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:[^@\s'"]{4,}@[^\s/'"]+)/i,
    minEntropy: 3.2,
    confidence: "HIGH",
    falsePositiveNote:
      "Localhost URIs with default passwords (e.g., 'postgres:postgres@localhost') may be used for local Docker Compose setups.",
    remediation:
      "Rotate the database user password, restrict network ingress via VPC security groups, and inject DATABASE_URL via runtime environment variables.",
  },
  {
    ruleId: "SEC-JWT-001",
    secretType: "JWT Bearer Token",
    severity: "MEDIUM",
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,})\b/,
    minEntropy: 4.0,
    confidence: "MEDIUM",
    falsePositiveNote:
      "Static JWTs in tests or public Supabase anon keys often match this structure. Inspect token claims (exp, role) to assess impact.",
    remediation:
      "If the token is a long-lived service role or production session JWT, rotate the signing secret and enforce short token expiration windows.",
  },
  {
    ruleId: "SEC-GEN-001",
    secretType: "Generic High-Entropy API Secret",
    severity: "HIGH",
    regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9/+_-]{24,80})['"]/i,
    minEntropy: 4.1,
    confidence: "MEDIUM",
    falsePositiveNote:
      "Heuristic match based on variable assignment and Shannon entropy >= 4.1 bits/char. Could match non-secret hashes or public identifiers.",
    remediation:
      "Verify if the value authenticates to an external service; if so, rotate the credential and move it to a managed secret store.",
  },
];

const BENIGN_PLACEHOLDER_PATTERNS = [
  /EXAMPLE/i,
  /YOUR_.*_HERE/i,
  /REPLACE_ME/i,
  /xxxx+/i,
  /\*\*\*\*+/,
  /00000000/,
  /12345678/,
  /process\.env\./i,
  /\$\{\{/,
];

/**
 * Performs static server-side secret detection across files.
 * Raw secret values are immediately masked and never stored or transmitted externally.
 */
export function scanForSecrets(
  files: { name: string; content: string }[]
): SecretFinding[] {
  const findings: SecretFinding[] = [];

  for (const file of files) {
    // Skip lockfiles for secret scanning to avoid matching SHA-512 integrity hashes
    if (/(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Gemfile\.lock)$/i.test(file.name)) {
      continue;
    }

    const lines = file.content.split(/\r?\n/);
    lines.forEach((line, idx) => {
      if (!line || line.length > 1000) return;

      for (const rule of SECRET_RULES) {
        const match = line.match(rule.regex);
        if (!match) continue;

        const candidate = match[1] ?? match[0];
        if (
          rule.ruleId !== "SEC-PK-001" &&
          BENIGN_PLACEHOLDER_PATTERNS.some((p) => p.test(candidate))
        ) {
          continue;
        }

        const entropy = calculateShannonEntropy(candidate);
        if (entropy < rule.minEntropy) continue;

        const maskedValue =
          rule.ruleId === "SEC-PK-001"
            ? "-----BEGIN PRIVATE KEY----- [REDACTED PEM BLOCK]"
            : maskSecretValue(candidate);

        findings.push({
          id: `${rule.ruleId}-${file.name}-L${idx + 1}`,
          ruleId: rule.ruleId,
          secretType: rule.secretType,
          severity: rule.severity,
          filePath: file.name,
          lineNumber: idx + 1,
          maskedValue,
          entropy,
          confidence: rule.confidence,
          falsePositiveNote: rule.falsePositiveNote,
          remediation: rule.remediation,
        });
        break; // Avoid duplicate rules firing on the exact same line secret
      }
    });
  }

  return findings;
}
