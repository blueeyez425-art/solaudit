import { NextRequest, NextResponse } from "next/server";
import { rules, scanFiles, scanContent } from "@solaudit/core";
import { fetchRustFilesFromRepo, GithubFetchError } from "@/lib/github";

export const runtime = "nodejs";
export const maxDuration = 30;

const MAX_UPLOAD_BYTES = 1_000_000; // 1 MB — plenty for a single .rs source file

function errorResponse(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

export async function POST(req: NextRequest) {
  const contentType = req.headers.get("content-type") ?? "";

  try {
    if (contentType.includes("multipart/form-data")) {
      const form = await req.formData();
      const file = form.get("file");

      if (!(file instanceof File)) {
        return errorResponse("No file was uploaded. Attach a single .rs source file.", 400);
      }
      if (!file.name.endsWith(".rs")) {
        return errorResponse("Only .rs (Rust) source files are supported.", 400);
      }
      if (file.size > MAX_UPLOAD_BYTES) {
        return errorResponse("That file is too large (max 1 MB).", 400);
      }

      const content = await file.text();
      const findings = scanContent(content, file.name, rules);
      const result = {
        scannedFiles: 1,
        findings,
        summary: tally(findings),
      };

      return NextResponse.json({ mode: "upload", fileName: file.name, result });
    }

    if (contentType.includes("application/json")) {
      const body = (await req.json()) as { repoUrl?: string };
      const repoUrl = body.repoUrl?.trim();

      if (!repoUrl) {
        return errorResponse("Provide a GitHub repository URL to scan.", 400);
      }

      const { files, truncated, ref } = await fetchRustFilesFromRepo(repoUrl);
      const result = scanFiles(files, rules);

      return NextResponse.json({ mode: "repo", repoUrl, ref, truncated, result });
    }

    return errorResponse("Unsupported request format.", 400);
  } catch (err) {
    if (err instanceof GithubFetchError) {
      return errorResponse(err.message, err.status);
    }
    console.error("[solaudit-web] scan failed:", err);
    return errorResponse("Something went wrong while scanning. Please try again.", 500);
  }
}

function tally(findings: { severity: string }[]) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const key = f.severity.toLowerCase() as keyof typeof summary;
    if (key in summary) summary[key]++;
  }
  return summary;
}
