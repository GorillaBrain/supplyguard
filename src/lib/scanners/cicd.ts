import { CiCdFinding, Severity } from "@/types/security";

interface CiCdRule {
  ruleId: string;
  title: string;
  severity: Severity;
  platform: "GitHub Actions" | "GitLab CI" | "Jenkins";
  testLine: (line: string, fullContent: string) => boolean;
  description: string;
  riskExplanation: string;
  remediation: string;
}

const GITHUB_ACTIONS_RULES: CiCdRule[] = [
  {
    ruleId: "GHA-001",
    title: "Unpinned Third-Party GitHub Action (Mutable Tag/Branch)",
    severity: "HIGH",
    platform: "GitHub Actions",
    testLine: (line) => {
      const m = line.match(/^\s*-?\s*uses:\s*([^\s#]+)/);
      if (!m) return false;
      const spec = m[1].replace(/^['"]|['"]$/g, "");
      if (spec.startsWith("./") || spec.startsWith("docker://")) return false;
      const [actionPath, ref] = spec.split("@");
      if (!actionPath || !ref) return false;
      // Official actions/* with major version are lower risk, but mutable branch/tags on 3rd party or non-40-hex SHA are flagged
      const isFullSha = /^[a-f0-9]{40}$/i.test(ref);
      if (isFullSha) return false;
      // Flag any non-SHA third-party action or mutable branch ref (@main, @master, @HEAD, @v*)
      return true;
    },
    description:
      "GitHub Action is referenced using a mutable Git tag or branch name instead of an immutable 40-character commit SHA.",
    riskExplanation:
      "If an upstream action publisher's repository or token is compromised (as occurred in the tj-actions/changed-files supply chain incident), attackers can repoint version tags (e.g., @v3) to malicious commits that steal runner secrets.",
    remediation:
      "Pin the action to a full 40-character commit SHA (e.g., uses: owner/action@a1b2c3d4e5f6...) and use Dependabot or Renovate to review SHA updates.",
  },
  {
    ruleId: "GHA-002",
    title: "Dangerous pull_request_target Workflow Trigger",
    severity: "CRITICAL",
    platform: "GitHub Actions",
    testLine: (line) => /^\s*pull_request_target\s*:/.test(line),
    description:
      "Workflow triggers on 'pull_request_target', which executes in the context of the base repository with write token access and access to repository secrets.",
    riskExplanation:
      "When combined with checking out or building untrusted code from a forked pull request, attackers can execute arbitrary commands with full access to repository secrets and GITHUB_TOKEN write permissions.",
    remediation:
      "Use 'pull_request' instead of 'pull_request_target' for building or testing PR code, or strictly avoid checking out untrusted PR head refs inside 'pull_request_target' jobs.",
  },
  {
    ruleId: "GHA-003",
    title: "Excessive Workflow Token Permissions (write-all)",
    severity: "HIGH",
    platform: "GitHub Actions",
    testLine: (line) =>
      /^\s*permissions\s*:\s*write-all/i.test(line) ||
      /^\s*contents\s*:\s*write/i.test(line),
    description:
      "Workflow grants broad write permissions to the default GITHUB_TOKEN.",
    riskExplanation:
      "If any step or third-party dependency in the job is compromised, overly broad GITHUB_TOKEN permissions allow modifying repository contents, pushing releases, or poisoning packages.",
    remediation:
      "Set top-level 'permissions: read-all' (or 'permissions: {}') and grant minimal scoped write permissions only to the specific job that requires them.",
  },
  {
    ruleId: "GHA-004",
    title: "Unsafe Untrusted Expression Interpolation in Shell Script",
    severity: "CRITICAL",
    platform: "GitHub Actions",
    testLine: (line) =>
      /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|commits|head_commit|discussion)\.[^}]+\}\}|\$\{\{\s*github\.head_ref\s*\}\}/i.test(
        line
      ),
    description:
      "Untrusted user-controlled GitHub event metadata (such as PR title, branch name, or commit message) is interpolated directly inside a workflow expression.",
    riskExplanation:
      "Attackers can craft a branch name or pull request title containing shell metacharacters (e.g., `$(curl ...)`), achieving arbitrary command injection on the CI runner before the shell script executes.",
    remediation:
      "Pass the expression through an environment variable (`env: PR_TITLE: ${{ github.event.pull_request.title }}`) and reference it safely in shell as `\"$PR_TITLE\"`.",
  },
  {
    ruleId: "GHA-005",
    title: "Remote Script Pipe Execution (curl/wget | sh)",
    severity: "HIGH",
    platform: "GitHub Actions",
    testLine: (line) =>
      /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python|node)\b/i.test(
        line
      ),
    description:
      "CI step downloads a remote script over the network and pipes it directly into a shell interpreter without cryptographic checksum verification.",
    riskExplanation:
      "If the remote domain or CDN is compromised (similar to the Codecov bash uploader supply chain attack), arbitrary malicious code executes immediately inside the CI environment with access to build secrets.",
    remediation:
      "Download the artifact to disk, verify its SHA-256 cryptographic digest against a pinned checksum, and only then execute it.",
  },
  {
    ruleId: "GHA-006",
    title: "Potential CI Secret Exposure to Standard Output",
    severity: "HIGH",
    platform: "GitHub Actions",
    testLine: (line) =>
      /(?:echo|printf|printenv|env)\b.*\$\{\{\s*secrets\.[^}]+\}\}/i.test(line) ||
      /\b(?:printenv|export\s+-p|set)\b.*>\s*[^\s]+/i.test(line),
    description:
      "Workflow command echoes or dumps secret context variables into standard output or an artifact file.",
    riskExplanation:
      "While GitHub attempts to redact exact single-line secret strings, multi-line secrets, base64-encoded transforms, or environment dumps written to build artifacts can expose credentials to anyone with read access to workflow logs.",
    remediation:
      "Never echo secrets or dump full environment variables in CI steps. Pass secrets strictly via scoped environment variables to the specific command that requires them.",
  },
];

const GITLAB_CI_RULES: CiCdRule[] = [
  {
    ruleId: "GLCI-001",
    title: "Unpinned Container Image Tag (:latest) in GitLab CI",
    severity: "MEDIUM",
    platform: "GitLab CI",
    testLine: (line) => /^\s*image:\s*[^\s#]+:latest\b/i.test(line),
    description:
      "GitLab CI job uses a mutable ':latest' container image tag rather than an immutable image digest.",
    riskExplanation:
      "Mutable container tags can be overwritten upstream, leading to non-reproducible builds or execution of tampered base images.",
    remediation:
      "Pin the runner image to a specific version and SHA-256 digest (e.g., image: node:22.11.0-alpine@sha256:...).",
  },
  {
    ruleId: "GLCI-002",
    title: "Remote Script Pipe Execution in GitLab CI Script",
    severity: "HIGH",
    platform: "GitLab CI",
    testLine: (line) =>
      /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i.test(line),
    description:
      "GitLab CI job pipes a remote script directly into a shell without integrity verification.",
    riskExplanation:
      "Compromise of the remote script host enables immediate credential harvesting of CI_JOB_TOKEN and masked project variables.",
    remediation:
      "Verify downloaded binaries/scripts with `sha256sum --check` before executing them in CI.",
  },
];

const JENKINS_RULES: CiCdRule[] = [
  {
    ruleId: "JENK-001",
    title: "Unsafe Groovy String Interpolation with Credentials in Jenkinsfile",
    severity: "HIGH",
    platform: "Jenkins",
    testLine: (line) =>
      /\bsh\s+"[^"]*\$\{?(?:env\.)?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY)[A-Z0-9_]*\}?[^"]*"/i.test(
        line
      ),
    description:
      "Jenkinsfile uses double-quoted Groovy string interpolation (`sh \"... ${SECRET} ...\"`) when passing sensitive variables to a shell step.",
    riskExplanation:
      "Groovy interpolates double-quoted strings on the Jenkins controller before passing the literal value to the shell agent, which can bypass credential masking in build logs and allow command injection.",
    remediation:
      "Use single-quoted strings in Jenkins shell steps (`sh 'cmd \"$SECRET\"'`) so the environment variable is resolved safely by the shell rather than Groovy.",
  },
];

/**
 * Performs static security analysis on GitHub Actions, GitLab CI, and Jenkins workflow files.
 * Never executes workflow files.
 */
export function analyzeCiCdFiles(
  files: { name: string; content: string }[]
): CiCdFinding[] {
  const findings: CiCdFinding[] = [];

  for (const file of files) {
    const lowerName = file.name.toLowerCase();
    const isGitHubWorkflow =
      lowerName.includes(".github/workflows/") ||
      (/workflow.*\.ya?ml$/i.test(lowerName) &&
        file.content.includes("jobs:") &&
        (file.content.includes("runs-on:") || file.content.includes("uses:")));
    const isGitLabCi = lowerName.endsWith(".gitlab-ci.yml") || lowerName.endsWith(".gitlab-ci.yaml");
    const isJenkins = lowerName.endsWith("jenkinsfile");

    if (!isGitHubWorkflow && !isGitLabCi && !isJenkins) continue;

    const rules = isGitHubWorkflow
      ? GITHUB_ACTIONS_RULES
      : isGitLabCi
      ? GITLAB_CI_RULES
      : JENKINS_RULES;

    const lines = file.content.split(/\r?\n/);
    lines.forEach((rawLine, idx) => {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) return;

      for (const rule of rules) {
        if (rule.testLine(rawLine, file.content)) {
          findings.push({
            id: `${rule.ruleId}-${file.name}-L${idx + 1}`,
            ruleId: rule.ruleId,
            title: rule.title,
            severity: rule.severity,
            platform: rule.platform,
            filePath: file.name,
            lineNumber: idx + 1,
            snippet: trimmed.slice(0, 140),
            description: rule.description,
            riskExplanation: rule.riskExplanation,
            remediation: rule.remediation,
          });
        }
      }
    });
  }

  return findings;
}
