#!/usr/bin/env node
import { rules, scanDirectory, printReport, toSarif, scanDeployedProgram, printDeployedReport } from "@solaudit/core";
import type { Severity } from "@solaudit/core";

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function printHelp(): void {
  console.log(`SolAudit — static analysis CLI for Anchor/Solana programs

Usage:
  solaudit [path] [options]
  solaudit --program <address> [options]

Arguments:
  path                    File or directory to scan (default: current directory)

Options:
  --program <address>     Analyze a deployed Solana program by its on-chain address
                          instead of local source. Checks upgrade-authority risk,
                          and scans the matching public source if the program has
                          a verified build on file (see https://verify.osec.io).
  --cluster <name>        Cluster for --program lookups: mainnet-beta (default),
                          devnet, or testnet
  --rpc <url>             Custom Solana RPC endpoint for --program lookups
                          (overrides --cluster's default public endpoint)
  --json                  Print raw scan results as JSON
  --sarif                 Print scan results as SARIF 2.1.0 JSON (for GitHub code scanning)
                          (not available with --program)
  --min-severity <level>  Only report findings at or above this severity
                          (CRITICAL | HIGH | MEDIUM | LOW | INFO)
  --help                  Show this help message

Examples:
  solaudit ./program
  bun run solaudit ./programs/vault --min-severity HIGH
  solaudit . --sarif > results.sarif
  solaudit --program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
  solaudit --program <address> --cluster devnet --json

Exit codes:
  0   No CRITICAL or HIGH severity findings
  1   One or more CRITICAL or HIGH severity findings were found
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  const wantsJson = args.includes("--json");
  const wantsSarif = args.includes("--sarif");

  const programIdx = args.indexOf("--program");
  if (programIdx !== -1) {
    const programId = args[programIdx + 1];
    if (!programId || programId.startsWith("-")) {
      console.error("[solaudit] --program requires a Solana program address argument");
      process.exit(2);
    }

    const clusterIdx = args.indexOf("--cluster");
    const cluster = (clusterIdx !== -1 ? args[clusterIdx + 1] : "mainnet-beta") as
      | "mainnet-beta"
      | "devnet"
      | "testnet";

    const rpcIdx = args.indexOf("--rpc");
    const rpcUrl = rpcIdx !== -1 ? args[rpcIdx + 1] : undefined;

    try {
      const result = await scanDeployedProgram(programId, { cluster, rpcUrl });

      if (wantsJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printDeployedReport(result);
      }

      const allFindings = [...result.onChainFindings, ...(result.sourceScan?.findings ?? [])];
      const hasBlocking = allFindings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      process.exit(hasBlocking ? 1 : 0);
    } catch (err) {
      console.error(`[solaudit] deployed program scan failed: ${(err as Error).message}`);
      process.exit(2);
    }
  }

  let minSeverity: Severity = "INFO";
  const minSeverityIdx = args.indexOf("--min-severity");
  if (minSeverityIdx !== -1) {
    const value = (args[minSeverityIdx + 1] || "").toUpperCase() as Severity;
    if (value in SEVERITY_RANK) {
      minSeverity = value;
    } else {
      console.error(`[solaudit] invalid --min-severity value: "${args[minSeverityIdx + 1]}"`);
      process.exit(2);
    }
  }

  const positional = args.filter((arg, idx) => {
    if (arg.startsWith("-")) return false;
    if (args[idx - 1] === "--min-severity") return false;
    return true;
  });

  const targetPath = positional[0] || ".";

  const result = await scanDirectory(targetPath, rules);

  result.findings = result.findings.filter(
    (finding) => SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[minSeverity]
  );

  if (wantsSarif) {
    console.log(JSON.stringify(toSarif(result), null, 2));
  } else if (wantsJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printReport(result);
  }

  const hasBlockingFindings = result.findings.some(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
  );

  process.exit(hasBlockingFindings ? 1 : 0);
}

main().catch((err) => {
  console.error(`[solaudit] fatal error: ${(err as Error).message}`);
  process.exit(2);
});
