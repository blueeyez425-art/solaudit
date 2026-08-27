import type { InMemoryFile } from "@solaudit/core";

export class GithubFetchError extends Error {
  constructor(
    message: string,
    public readonly status: number
  ) {
    super(message);
    this.name = "GithubFetchError";
  }
}

/** Hard safety limits so a single scan request can't be used to abuse GitHub's API or our function runtime. */
const MAX_FILES = 150;
const MAX_FILE_BYTES = 400_000; // 400 KB — generous for a single .rs source file
const MAX_TOTAL_BYTES = 15_000_000; // 15 MB across the whole repo scan
const FETCH_TIMEOUT_MS = 8_000;
const CONCURRENCY = 10;

export interface ParsedRepo {
  owner: string;
  repo: string;
  ref?: string;
}

/**
 * Accepts a GitHub repo URL in common forms:
 *   https://github.com/owner/repo
 *   https://github.com/owner/repo.git
 *   https://github.com/owner/repo/tree/branch
 *   owner/repo
 */
export function parseGithubUrl(input: string): ParsedRepo {
  const trimmed = input.trim();

  const shorthand = trimmed.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (shorthand) {
    return { owner: shorthand[1], repo: shorthand[2] };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new GithubFetchError(
      "That doesn't look like a valid GitHub URL. Try a format like https://github.com/owner/repo",
      400
    );
  }

  if (url.hostname !== "github.com" && url.hostname !== "www.github.com") {
    throw new GithubFetchError("Only github.com repository URLs are supported right now.", 400);
  }

  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 2) {
    throw new GithubFetchError(
      "Couldn't find an owner and repo name in that URL. Try https://github.com/owner/repo",
      400
    );
  }

  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, "");
  let ref: string | undefined;

  if (parts[2] === "tree" && parts[3]) {
    ref = decodeURIComponent(parts.slice(3).join("/"));
  }

  return { owner, repo, ref };
}

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function authHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN;
  const headers: Record<string, string> = { Accept: "application/vnd.github+json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function resolveDefaultBranch(owner: string, repo: string): Promise<string> {
  const res = await fetchWithTimeout(`https://api.github.com/repos/${owner}/${repo}`, {
    headers: authHeaders(),
  });

  if (res.status === 404) {
    throw new GithubFetchError(
      `Repository "${owner}/${repo}" wasn't found. Check that it's spelled correctly and public.`,
      404
    );
  }
  if (res.status === 403) {
    throw new GithubFetchError(
      "GitHub's API rate limit was hit. Please try again in a few minutes.",
      403
    );
  }
  if (!res.ok) {
    throw new GithubFetchError(`GitHub API returned an unexpected error (${res.status}).`, res.status);
  }

  const data = (await res.json()) as { default_branch?: string; private?: boolean };
  if (data.private) {
    throw new GithubFetchError("Private repositories aren't supported — please use a public repo.", 400);
  }
  return data.default_branch ?? "main";
}

interface GitTreeEntry {
  path: string;
  type: "blob" | "tree" | "commit";
  size?: number;
  sha: string;
}

/**
 * Fetches every `.rs` file from a public GitHub repo via the Git Trees + raw content APIs
 * (no `git clone`, which keeps this safe and fast to run inside a serverless function).
 */
export async function fetchRustFilesFromRepo(repoUrl: string): Promise<{
  files: InMemoryFile[];
  truncated: boolean;
  ref: string;
}> {
  const { owner, repo, ref: requestedRef } = parseGithubUrl(repoUrl);
  const ref = requestedRef ?? (await resolveDefaultBranch(owner, repo));

  const treeRes = await fetchWithTimeout(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`,
    { headers: authHeaders() }
  );

  if (treeRes.status === 404) {
    throw new GithubFetchError(
      `Couldn't find branch/ref "${ref}" on ${owner}/${repo}.`,
      404
    );
  }
  if (treeRes.status === 403) {
    throw new GithubFetchError("GitHub's API rate limit was hit. Please try again in a few minutes.", 403);
  }
  if (!treeRes.ok) {
    throw new GithubFetchError(`GitHub API returned an unexpected error (${treeRes.status}).`, treeRes.status);
  }

  const treeData = (await treeRes.json()) as { tree: GitTreeEntry[]; truncated?: boolean };

  const rustBlobs = treeData.tree.filter(
    (entry) =>
      entry.type === "blob" &&
      entry.path.endsWith(".rs") &&
      !entry.path.includes("/target/") &&
      !entry.path.startsWith("target/") &&
      (entry.size ?? 0) <= MAX_FILE_BYTES
  );

  if (rustBlobs.length === 0) {
    throw new GithubFetchError(
      "No .rs files were found in that repository (or they were all too large to scan).",
      404
    );
  }

  const capped = rustBlobs.slice(0, MAX_FILES);
  const wasCapped = rustBlobs.length > MAX_FILES || Boolean(treeData.truncated);

  const files: InMemoryFile[] = [];
  let totalBytes = 0;

  for (let i = 0; i < capped.length; i += CONCURRENCY) {
    const batch = capped.slice(i, i + CONCURRENCY);
    const results = await Promise.all(
      batch.map(async (entry) => {
        const raw = await fetchWithTimeout(
          `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(ref)}/${entry.path}`
        );
        if (!raw.ok) return null;
        const content = await raw.text();
        return { path: entry.path, content };
      })
    );

    for (const result of results) {
      if (!result) continue;
      totalBytes += result.content.length;
      if (totalBytes > MAX_TOTAL_BYTES) {
        return { files, truncated: true, ref };
      }
      files.push(result);
    }
  }

  return { files, truncated: wasCapped, ref };
}
