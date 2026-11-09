import { NextRequest, NextResponse } from "next/server";
import {
  checkRateLimit,
  MAX_TOTAL_UPLOAD_BYTES,
  ScanRequestSchema,
  validateGitHubRepositoryUrl,
} from "@/lib/security/ssrf";
import { fetchGitHubRepositoryFiles } from "@/lib/scanners/github-fetcher";
import { runFullSecurityScan } from "@/lib/scanners/orchestrator";
import { getSeededDemoReports } from "@/lib/demo-fixtures";

export async function GET() {
  try {
    const demoReports = await getSeededDemoReports();
    return NextResponse.json({
      ok: true,
      mode: "demo",
      reports: demoReports,
    });
  } catch {
    return NextResponse.json(
      { ok: false, error: "Failed to initialize benchmark reports." },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  const clientIp =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "local-client";
  const rateStatus = checkRateLimit(clientIp);

  if (!rateStatus.allowed) {
    return NextResponse.json(
      {
        ok: false,
        error: `Rate limit exceeded. Try again in ${rateStatus.resetInSeconds} seconds.`,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(rateStatus.resetInSeconds),
        },
      }
    );
  }

  let rawBody: unknown;
  try {
    const bodyText = await request.text();
    if (bodyText.length > MAX_TOTAL_UPLOAD_BYTES) {
      return NextResponse.json(
        {
          ok: false,
          error: "Payload exceeds maximum allowed upload size of 12 MB.",
        },
        { status: 413 }
      );
    }
    rawBody = JSON.parse(bodyText);
  } catch {
    return NextResponse.json(
      { ok: false, error: "Malformed JSON request body." },
      { status: 400 }
    );
  }

  const parsed = ScanRequestSchema.safeParse(rawBody);
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0];
    return NextResponse.json(
      {
        ok: false,
        error: firstIssue
          ? `${firstIssue.path.join(".") || "request"}: ${firstIssue.message}`
          : "Invalid scan request parameters.",
      },
      { status: 400 }
    );
  }

  const { mode, repositoryUrl, projectName, internalPrefixes, files } =
    parsed.data;

  try {
    if (mode === "demo") {
      const demoReports = await getSeededDemoReports();
      return NextResponse.json({
        ok: true,
        report: demoReports[0],
      });
    }

    if (mode === "github") {
      const urlCheck = validateGitHubRepositoryUrl(repositoryUrl ?? "");
      if (!urlCheck.valid || !urlCheck.data) {
        return NextResponse.json(
          {
            ok: false,
            error: urlCheck.error ?? "Rejected repository URL.",
          },
          { status: 400 }
        );
      }

      const repoData = await fetchGitHubRepositoryFiles(
        urlCheck.data.normalizedUrl
      );
      const report = await runFullSecurityScan({
        projectName: projectName?.trim() || repoData.projectName,
        sourceType: "github",
        repositoryUrl: repoData.normalizedUrl,
        isDemoData: false,
        files: repoData.files,
        internalPrefixes,
      });

      report.intelligenceStatus.notes.unshift(...repoData.notes);

      return NextResponse.json({
        ok: true,
        report,
      });
    }

    // Mode === "upload"
    const uploadedFiles = files ?? [];
    const isSbomUpload = uploadedFiles.some(
      (f) =>
        /(?:bom|cdx|spdx)/i.test(f.name) ||
        f.content.includes('"bomFormat"') ||
        f.content.includes('"spdxVersion"')
    );

    const report = await runFullSecurityScan({
      projectName:
        projectName?.trim() ||
        uploadedFiles[0]?.name.replace(/\.[^.]+$/, "") ||
        "Uploaded Project Analysis",
      sourceType: isSbomUpload ? "sbom" : "upload",
      isDemoData: false,
      files: uploadedFiles,
      internalPrefixes,
    });

    return NextResponse.json({
      ok: true,
      report,
    });
  } catch (err) {
    const safeMessage =
      err instanceof Error
        ? err.message
        : "An unexpected error occurred during scanning.";
    return NextResponse.json(
      {
        ok: false,
        error: safeMessage,
      },
      { status: 422 }
    );
  }
}
