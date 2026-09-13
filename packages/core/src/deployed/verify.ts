/**
 * Client for OtterSec's public Solana Verified Builds registry
 * (https://verify.osec.io) — an open, free API that maps a deployed
 * program's on-chain hash back to a public GitHub repo + commit, when the
 * program's developer opted in to a verifiable build.
 *
 * This is what makes real source-level scanning of a *deployed* program
 * possible without reverse-engineering raw bytecode: if a program is
 * verified, we know exactly which GitHub source produced it.
 */

const VERIFY_API_BASE = "https://verify.osec.io";

export interface VerificationStatus {
  isVerified: boolean;
  message: string;
  repoUrl: string | null;
  commit: string | null;
  isFrozen: boolean;
  isClosed: boolean;
}

export async function checkVerification(programId: string): Promise<VerificationStatus> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  let res: Response;
  try {
    res = await fetch(`${VERIFY_API_BASE}/status/${programId}`, { signal: controller.signal });
  } catch (err) {
    throw new Error(`Failed to reach verify.osec.io: ${(err as Error).message}`);
  } finally {
    clearTimeout(timeout);
  }

  if (!res.ok) {
    // The API returns non-200 for programs it has never seen — treat as "not verified" rather than a hard error.
    return { isVerified: false, message: "Program not found in the verified builds registry.", repoUrl: null, commit: null, isFrozen: false, isClosed: false };
  }

  const data = (await res.json()) as {
    is_verified?: boolean;
    message?: string;
    repo_url?: string | null;
    commit?: string | null;
    is_frozen?: boolean;
    is_closed?: boolean;
  };

  return {
    isVerified: Boolean(data.is_verified),
    message: data.message ?? "",
    repoUrl: data.repo_url ?? null,
    commit: data.commit && data.commit !== "None" ? data.commit : null,
    isFrozen: Boolean(data.is_frozen),
    isClosed: Boolean(data.is_closed),
  };
}
