import { z } from "zod";

export const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB per file
export const MAX_TOTAL_UPLOAD_BYTES = 12 * 1024 * 1024; // 12 MB total payload
export const MAX_FILES_PER_SCAN = 25;

const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^169\.254\.\d+\.\d+$/, // AWS/Cloud metadata link-local
  /^0\.0\.0\.0$/,
  /^\[?::1\]?$/,
  /^\[?fc00:/i,
  /^\[?fe80:/i,
  /\.internal$/i,
  /\.local$/i,
  /metadata\.google\.internal/i,
];

export interface ValidatedGitHubRepo {
  owner: string;
  repo: string;
  branch?: string;
  normalizedUrl: string;
}

/**
 * Validates and normalizes a public GitHub repository URL.
 * Strictly prevents SSRF by enforcing HTTPS, exact hostname matching (`github.com`),
 * blocking credentials, custom ports, path traversal, and private/internal hosts.
 */
export function validateGitHubRepositoryUrl(rawUrl: string): {
  valid: boolean;
  data?: ValidatedGitHubRepo;
  error?: string;
} {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return { valid: false, error: "Repository URL cannot be empty." };
  }

  let decodedRaw = trimmed;
  try {
    decodedRaw = decodeURIComponent(trimmed);
  } catch {
    return { valid: false, error: "Malformed URL encoding." };
  }

  if (decodedRaw.includes("..") || trimmed.includes("..")) {
    return {
      valid: false,
      error: "Path traversal segments ('..') are not allowed.",
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      valid: false,
      error: "Invalid URL format. Provide a full HTTPS URL such as https://github.com/owner/repo.",
    };
  }

  if (parsed.protocol !== "https:") {
    return {
      valid: false,
      error: "Only HTTPS URLs are permitted (http://, file://, and custom schemes are blocked).",
    };
  }

  if (parsed.username || parsed.password) {
    return {
      valid: false,
      error: "Embedded credentials in URLs are forbidden.",
    };
  }

  if (parsed.port && parsed.port !== "443") {
    return {
      valid: false,
      error: "Non-standard ports are blocked by SSRF policy.",
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (PRIVATE_HOST_PATTERNS.some((pattern) => pattern.test(hostname))) {
    return {
      valid: false,
      error: "SSRF Protection: Private, loopback, and link-local network addresses are strictly blocked.",
    };
  }

  if (hostname !== "github.com" && hostname !== "www.github.com") {
    return {
      valid: false,
      error: "Only public github.com repositories are allowed for remote repository fetching.",
    };
  }

  const rawSegments = parsed.pathname.split("/").filter(Boolean);
  if (rawSegments.some((s) => s === "." || s === ".." || s.includes(".."))) {
    return {
      valid: false,
      error: "Path traversal segments ('..') are not allowed.",
    };
  }

  const segments = rawSegments.filter((s) => s !== "." && s !== "..");
  if (segments.length < 2) {
    return {
      valid: false,
      error: "URL must include both repository owner and name (e.g., https://github.com/owner/repository).",
    };
  }

  const owner = segments[0];
  const repo = segments[1].replace(/\.git$/i, "");

  const safeIdentifier = /^[a-zA-Z0-9._-]+$/;
  if (!safeIdentifier.test(owner) || !safeIdentifier.test(repo) || owner === "." || owner === "..") {
    return {
      valid: false,
      error: "Invalid GitHub owner or repository name characters.",
    };
  }

  let branch: string | undefined;
  if (segments[2] === "tree" && segments[3]) {
    const candidateBranch = segments.slice(3).join("/");
    if (/^[a-zA-Z0-9._/-]+$/.test(candidateBranch) && !candidateBranch.includes("..")) {
      branch = candidateBranch;
    }
  }

  return {
    valid: true,
    data: {
      owner,
      repo,
      branch,
      normalizedUrl: `https://github.com/${owner}/${repo}`,
    },
  };
}

/**
 * Safe fetch wrapper that restricts outbound requests strictly to allowlisted API hosts
 * and disables redirects to untrusted hosts.
 */
const ALLOWED_OUTBOUND_HOSTS = new Set([
  "api.github.com",
  "raw.githubusercontent.com",
  "api.osv.dev",
  "registry.npmjs.org",
  "pypi.org",
]);

export async function safeExternalFetch(
  url: string,
  init?: RequestInit & { timeoutMs?: number }
): Promise<Response> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`SSRF Policy Violation: Non-HTTPS outbound request blocked (${parsed.protocol})`);
  }
  if (!ALLOWED_OUTBOUND_HOSTS.has(parsed.hostname.toLowerCase())) {
    throw new Error(`SSRF Policy Violation: Host '${parsed.hostname}' is not in the outbound allowlist.`);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), init?.timeoutMs ?? 8000);

  try {
    const response = await fetch(url, {
      ...init,
      redirect: "error", // Prevent open-redirect SSRF to internal networks
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(timeout);
  }
}

export const SUPPORTED_FILE_PATTERNS: {
  pattern: RegExp;
  type: "manifest" | "lockfile" | "sbom" | "cicd" | "config" | "source";
  ecosystem?: string;
}[] = [
  { pattern: /(?:^|\/)package\.json$/i, type: "manifest", ecosystem: "npm" },
  { pattern: /(?:^|\/)package-lock\.json$/i, type: "lockfile", ecosystem: "npm" },
  { pattern: /(?:^|\/)npm-shrinkwrap\.json$/i, type: "lockfile", ecosystem: "npm" },
  { pattern: /(?:^|\/)pnpm-lock\.yaml$/i, type: "lockfile", ecosystem: "npm" },
  { pattern: /(?:^|\/)yarn\.lock$/i, type: "lockfile", ecosystem: "npm" },
  { pattern: /(?:^|\/)\.npmrc$/i, type: "config", ecosystem: "npm" },
  { pattern: /(?:^|\/)requirements(?:-[a-z0-9_]+)?\.txt$/i, type: "manifest", ecosystem: "PyPI" },
  { pattern: /(?:^|\/)poetry\.lock$/i, type: "lockfile", ecosystem: "PyPI" },
  { pattern: /(?:^|\/)Pipfile\.lock$/i, type: "lockfile", ecosystem: "PyPI" },
  { pattern: /(?:^|\/)pip\.conf$/i, type: "config", ecosystem: "PyPI" },
  { pattern: /(?:^|\/)Gemfile\.lock$/i, type: "lockfile", ecosystem: "RubyGems" },
  { pattern: /(?:^|\/)Gemfile$/i, type: "manifest", ecosystem: "RubyGems" },
  { pattern: /(?:^|\/)pom\.xml$/i, type: "manifest", ecosystem: "Maven" },
  { pattern: /(?:^|\/).*bom.*\.(?:json|xml)$/i, type: "sbom", ecosystem: "SBOM" },
  { pattern: /(?:^|\/).*\.cdx\.json$/i, type: "sbom", ecosystem: "SBOM" },
  { pattern: /(?:^|\/).*\.spdx\.json$/i, type: "sbom", ecosystem: "SBOM" },
  { pattern: /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i, type: "cicd" },
  { pattern: /(?:^|\/)[^/]*workflow[^/]*\.ya?ml$/i, type: "cicd" },
  { pattern: /(?:^|\/)\.gitlab-ci\.ya?ml$/i, type: "cicd" },
  { pattern: /(?:^|\/)Jenkinsfile$/i, type: "cicd" },
  { pattern: /\.(?:env|env\.example|js|ts|py|rb|java|yml|yaml|json|sh|properties)$/i, type: "source" },
];

export const UploadedFileSchema = z.object({
  name: z
    .string()
    .min(1, "File name is required")
    .max(260, "File path exceeds maximum length")
    .refine((name) => !name.includes("\0") && !name.includes(".."), {
      message: "Invalid path characters detected",
    }),
  content: z
    .string()
    .max(MAX_FILE_SIZE_BYTES, `File content exceeds maximum size of 5 MB`),
});

export const ScanRequestSchema = z
  .object({
    mode: z.enum(["github", "upload", "demo"]),
    repositoryUrl: z.string().optional(),
    projectName: z.string().max(120).optional(),
    internalPrefixes: z.array(z.string().max(64)).max(20).optional(),
    files: z.array(UploadedFileSchema).max(MAX_FILES_PER_SCAN).optional(),
  })
  .superRefine((val, ctx) => {
    if (val.mode === "github" && !val.repositoryUrl) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "A valid GitHub repository URL is required when mode is 'github'.",
        path: ["repositoryUrl"],
      });
    }
    if (val.mode === "upload" && (!val.files || val.files.length === 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "At least one dependency manifest, lockfile, SBOM, or workflow file is required.",
        path: ["files"],
      });
    }
  });

// In-memory sliding window rate limiter per IP
const rateLimitStore = new Map<string, number[]>();
const WINDOW_MS = 60_000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 30;

export function checkRateLimit(clientKey: string): {
  allowed: boolean;
  remaining: number;
  resetInSeconds: number;
} {
  const now = Date.now();
  const timestamps = (rateLimitStore.get(clientKey) ?? []).filter(
    (t) => now - t < WINDOW_MS
  );
  if (timestamps.length >= MAX_REQUESTS_PER_WINDOW) {
    const oldest = timestamps[0] ?? now;
    return {
      allowed: false,
      remaining: 0,
      resetInSeconds: Math.ceil((WINDOW_MS - (now - oldest)) / 1000),
    };
  }
  timestamps.push(now);
  rateLimitStore.set(clientKey, timestamps);
  return {
    allowed: true,
    remaining: MAX_REQUESTS_PER_WINDOW - timestamps.length,
    resetInSeconds: 60,
  };
}
