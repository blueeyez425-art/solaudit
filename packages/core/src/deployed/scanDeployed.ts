import { scanFiles } from "../scanner";
import { rules } from "../rules/index";
import type { Finding, ScanResult } from "../types";
import { DEFAULT_RPC_ENDPOINTS, getUpgradeAuthority, isValidPubkey, RpcError } from "./rpc";
import { checkVerification } from "./verify";
import { fetchRustFilesFromRepo, GithubFetchError } from "./githubFetch";

export interface DeployedScanResult {
  programId: string;
  cluster: string;
  /** True if a verified public source repo was found and scanned. */
  sourceScanned: boolean;
  repoUrl: string | null;
  /** Full static-analysis findings from the verified source, when available. */
  sourceScan: ScanResult | null;
  /** On-chain risk findings that apply regardless of source availability (upgrade authority, etc). */
  onChainFindings: Finding[];
  warnings: string[];
}

const ON_CHAIN_FILE_PATH = "<on-chain>";

function upgradeAuthorityFinding(
  programId: string,
  upgradeable: boolean,
  authority: string | null
): Finding {
  if (!upgradeable) {
    return {
      ruleId: "SOL-D01",
      ruleName: "Immutable Program",
      severity: "INFO",
      filePath: ON_CHAIN_FILE_PATH,
      line: 0,
      snippet: programId,
      description:
        "This program is not deployed with the upgradeable BPF loader — its code cannot be changed after deployment.",
    };
  }

  if (authority === null) {
    return {
      ruleId: "SOL-D01",
      ruleName: "Upgrade Authority Revoked",
      severity: "INFO",
      filePath: ON_CHAIN_FILE_PATH,
      line: 0,
      snippet: programId,
      description:
        "This program was deployed as upgradeable, but its upgrade authority has been set to None (revoked) — the code is now effectively immutable.",
    };
  }

  return {
    ruleId: "SOL-D02",
    ruleName: "Active Upgrade Authority",
    severity: "HIGH",
    filePath: ON_CHAIN_FILE_PATH,
    line: 0,
    snippet: authority,
    description:
      `This program can be upgraded at any time by account ${authority}. Anyone interacting with this program is trusting that account (and its key custody) not to push malicious code. Verify who controls this key (ideally a multisig/timelock) before treating this program as trustworthy.`,
  };
}

export interface ScanDeployedOptions {
  cluster?: "mainnet-beta" | "devnet" | "testnet";
  rpcUrl?: string;
}

/**
 * Analyze a deployed Solana program by address.
 *
 * Full reverse-engineering of arbitrary on-chain BPF/SBF bytecode is out of
 * scope (a large, separate research problem). Instead this combines two real,
 * verifiable signals:
 *
 *  1. On-chain upgrade authority risk (always available, no source needed) —
 *     is the program mutable, and if so, who can change it?
 *  2. Verified source-level scanning — if the program's developer published a
 *     verifiable build (via https://verify.osec.io), we know the exact public
 *     GitHub source that produced the on-chain bytecode, and we run SolAudit's
 *     full rule engine against that real source, same as scanning it locally.
 *
 * Unverified programs still get the on-chain upgrade-authority analysis; they
 * just won't have source-level findings, and that is reported explicitly
 * rather than silently omitted.
 */
export async function scanDeployedProgram(
  programId: string,
  options: ScanDeployedOptions = {}
): Promise<DeployedScanResult> {
  if (!isValidPubkey(programId)) {
    throw new Error(`"${programId}" is not a valid Solana program address (expected a base58-encoded 32-byte pubkey).`);
  }

  const cluster = options.cluster ?? "mainnet-beta";
  const rpcUrl = options.rpcUrl ?? DEFAULT_RPC_ENDPOINTS[cluster];
  if (!rpcUrl) {
    throw new Error(`Unknown cluster "${cluster}". Use mainnet-beta, devnet, testnet, or pass --rpc.`);
  }

  const warnings: string[] = [];
  const onChainFindings: Finding[] = [];

  try {
    const authorityInfo = await getUpgradeAuthority(rpcUrl, programId);
    onChainFindings.push(upgradeAuthorityFinding(programId, authorityInfo.isUpgradeable, authorityInfo.upgradeAuthority));
  } catch (err) {
    if (err instanceof RpcError) {
      warnings.push(`On-chain upgrade authority check failed: ${err.message}`);
    } else {
      throw err;
    }
  }

  let repoUrl: string | null = null;
  let sourceScan: ScanResult | null = null;
  let sourceScanned = false;

  try {
    const verification = await checkVerification(programId);
    if (verification.isVerified && verification.repoUrl) {
      repoUrl = verification.repoUrl;
      try {
        const { files, truncated } = await fetchRustFilesFromRepo(repoUrl);
        sourceScan = scanFiles(files, rules);
        sourceScanned = true;
        if (truncated) {
          warnings.push("The verified source repo is large — only a subset of .rs files were scanned.");
        }
      } catch (err) {
        if (err instanceof GithubFetchError) {
          warnings.push(`Program is verified against ${repoUrl}, but fetching its source failed: ${err.message}`);
        } else {
          throw err;
        }
      }
    } else {
      warnings.push(
        "This program has no verified build on file (verify.osec.io). Only on-chain upgrade-authority analysis is available — the deployed bytecode itself was not source-scanned. Ask the program's team to publish a verified build for full analysis."
      );
    }
  } catch (err) {
    warnings.push(`Verification registry lookup failed: ${(err as Error).message}`);
  }

  return {
    programId,
    cluster,
    sourceScanned,
    repoUrl,
    sourceScan,
    onChainFindings,
    warnings,
  };
}
