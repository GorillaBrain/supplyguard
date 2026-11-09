import { NextRequest, NextResponse } from "next/server";
import { generateCycloneDxSbom } from "@/lib/reports/exporter";
import { ScanReport } from "@/types/security";

export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as { report?: ScanReport };
    if (!body?.report || !Array.isArray(body.report.dependencies)) {
      return NextResponse.json(
        { ok: false, error: "Valid ScanReport payload is required." },
        { status: 400 }
      );
    }

    const sbom = generateCycloneDxSbom(body.report);
    return NextResponse.json({
      ok: true,
      sbom,
    });
  } catch {
    return NextResponse.json(
      { ok: false, error: "Failed to generate CycloneDX SBOM." },
      { status: 400 }
    );
  }
}
