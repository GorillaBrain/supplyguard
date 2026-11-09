import {
  safeExternalFetch,
  validateGitHubRepositoryUrl,
  MAX_FILE_SIZE_BYTES,
} from "@/lib/security/ssrf";

const CANDIDATE_FILE_REGEX =
  /(?:^|\/)(?:package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|\.npmrc|requirements(?:-[a-z0-9_]+)?\.txt|poetry\.lock|Pipfile\.lock|pip\.conf|Gemfile\.lock|pom\.xml|Jenkinsfile|\.gitlab-ci\.ya?ml|\.github\/workflows\/[^/]+\.ya?ml|[^/]*bom[^/]*\.json)$/i;

const FALLBACK_COMMON_PATHS = [
  "package-lock.json",
  "package.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  ".npmrc",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
  "Gemfile.lock",
  "pom.xml",
  ".github/workflows/ci.yml",
  ".github/workflows/build.yml",
  ".github/workflows/deploy.yml",
  ".github/workflows/release.yml",
  ".gitlab-ci.yml",
];

export async function fetchGitHubRepositoryFiles(rawUrl: string): Promise<{
  projectName: string;
  normalizedUrl: string;
  files: { name: string; content: string }[];
  notes: string[];
}> {
  const validation = validateGitHubRepositoryUrl(rawUrl);
  if (!validation.valid || !validation.data) {
    throw new Error(validation.error ?? "Invalid GitHub repository URL.");
  }

  const { owner, repo, branch, normalizedUrl } = validation.data;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "SupplyGuard-Security-Scanner/1.0",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  const notes: string[] = [];
  let defaultBranch = branch || "main";
  let targetPaths: string[] = [];

  try {
    // 1. Fetch repository metadata to verify existence and resolve default_branch
    const repoResp = await safeExternalFetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
      { headers, timeoutMs: 6000 }
    );

    if (repoResp.status === 404) {
      throw new Error(
        `Repository '${owner}/${repo}' was not found or is private. SupplyGuard scans public GitHub repositories.`
      );
    }

    if (repoResp.ok) {
      const repoJson = (await repoResp.json()) as { default_branch?: string };
      if (!branch && repoJson.default_branch) {
        defaultBranch = repoJson.default_branch;
      }

      // 2. Fetch repository git tree to discover manifests, lockfiles, and CI workflows
      const treeResp = await safeExternalFetch(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(
          repo
        )}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
        { headers, timeoutMs: 6500 }
      );

      if (treeResp.ok) {
        const treeData = (await treeResp.json()) as {
          tree?: { path?: string; type?: string; size?: number }[];
        };
        const allBlobs = (treeData.tree ?? []).filter(
          (item) =>
            item.type === "blob" &&
            item.path &&
            (item.size ?? 0) <= MAX_FILE_SIZE_BYTES &&
            CANDIDATE_FILE_REGEX.test(item.path)
        );
        targetPaths = allBlobs.map((b) => b.path!).slice(0, 18);
      }
    } else if (repoResp.status === 403 || repoResp.status === 429) {
      notes.push(
        "GitHub API rate limit reached for unauthenticated discovery; falling back to direct raw manifest probing."
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("not found")) {
      throw err;
    }
    notes.push(
      "Used direct raw.githubusercontent.com manifest probing for repository inspection."
    );
  }

  if (targetPaths.length === 0) {
    targetPaths = FALLBACK_COMMON_PATHS;
  }

  const fetchedFiles: { name: string; content: string }[] = [];
  const branchesToTry = branch ? [branch] : [defaultBranch, "master"];

  for (const candidateBranch of branchesToTry) {
    await Promise.all(
      targetPaths.map(async (filePath) => {
        if (fetchedFiles.some((f) => f.name === filePath)) return;
        const rawFileUrl = `https://raw.githubusercontent.com/${encodeURIComponent(
          owner
        )}/${encodeURIComponent(repo)}/${encodeURIComponent(
          candidateBranch
        )}/${filePath
          .split("/")
          .map((seg) => encodeURIComponent(seg))
          .join("/")}`;

        try {
          const resp = await safeExternalFetch(rawFileUrl, { timeoutMs: 5500 });
          if (resp.ok) {
            const text = await resp.text();
            if (text && text.length <= MAX_FILE_SIZE_BYTES) {
              fetchedFiles.push({ name: filePath, content: text });
            }
          }
        } catch {
          // Ignore individual missing fallback paths
        }
      })
    );
    if (fetchedFiles.length > 0) break;
  }

  if (fetchedFiles.length === 0) {
    throw new Error(
      `No supported dependency manifests, lockfiles, or CI/CD workflows were found in '${owner}/${repo}'.`
    );
  }

  notes.push(
    `Fetched ${fetchedFiles.length} security-relevant manifest/workflow file(s) from ${owner}/${repo}@${defaultBranch}.`
  );

  return {
    projectName: `${owner}/${repo}`,
    normalizedUrl,
    files: fetchedFiles,
    notes,
  };
}
