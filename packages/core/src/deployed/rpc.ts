import { base58Decode, base58Encode } from "./base58";

/** Owner program IDs for Solana's two BPF loaders. */
export const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
export const BPF_LOADER_2 = "BPFLoader2111111111111111111111111111111111";

export const DEFAULT_RPC_ENDPOINTS: Record<string, string> = {
  "mainnet-beta": "https://api.mainnet-beta.solana.com",
  devnet: "https://api.devnet.solana.com",
  testnet: "https://api.testnet.solana.com",
};

export class RpcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RpcError";
  }
}

interface AccountInfo {
  owner: string;
  data: Uint8Array;
  executable: boolean;
  lamports: number;
}

async function rpcCall<T>(endpoint: string, method: string, params: unknown[]): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  let res: Response;
  try {
    res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: controller.signal,
    });
  } catch (err) {
    throw new RpcError(`Failed to reach RPC endpoint ${endpoint}: ${(err as Error).message}`);
  } finally {
    clearTimeout(timeout);
  }

  if (!res.ok) {
    throw new RpcError(`RPC endpoint ${endpoint} returned HTTP ${res.status}`);
  }

  const body = (await res.json()) as { result?: T; error?: { message: string } };
  if (body.error) {
    throw new RpcError(`RPC error from ${endpoint}: ${body.error.message}`);
  }
  return body.result as T;
}

/** Fetch and decode an account's raw data + owner via `getAccountInfo`. Returns null if the account doesn't exist. */
export async function getAccountInfo(endpoint: string, address: string): Promise<AccountInfo | null> {
  const result = await rpcCall<{
    value: { owner: string; data: [string, string]; executable: boolean; lamports: number } | null;
  }>(endpoint, "getAccountInfo", [address, { encoding: "base64" }]);

  if (!result?.value) return null;

  const [dataB64] = result.value.data;
  return {
    owner: result.value.owner,
    data: new Uint8Array(Buffer.from(dataB64, "base64")),
    executable: result.value.executable,
    lamports: result.value.lamports,
  };
}

export interface UpgradeAuthorityInfo {
  /** True if the program was deployed with the upgradeable BPF loader. */
  isUpgradeable: boolean;
  /** The current upgrade authority pubkey, or null if the program is immutable (authority revoked, or a legacy non-upgradeable deploy). */
  upgradeAuthority: string | null;
  /** The address of the ProgramData account backing this program, if upgradeable. */
  programDataAddress: string | null;
}

/**
 * Determine whether a deployed program is upgradeable, and if so, who currently
 * holds the upgrade authority. A present, non-null authority means that account
 * can silently replace the program's code at any time — a real, well-documented
 * Solana risk (see https://solana.com/docs/programs/upgradeable-loader).
 */
export async function getUpgradeAuthority(endpoint: string, programId: string): Promise<UpgradeAuthorityInfo> {
  const programAccount = await getAccountInfo(endpoint, programId);
  if (!programAccount) {
    throw new RpcError(`No account found for program ID "${programId}" on this cluster.`);
  }
  if (!programAccount.executable) {
    throw new RpcError(`Account "${programId}" exists but is not marked executable — it is not a deployed program.`);
  }

  if (programAccount.owner !== BPF_LOADER_UPGRADEABLE) {
    // Owned by the legacy non-upgradeable loader (or something else executable) -> no upgrade authority concept applies.
    return { isUpgradeable: false, upgradeAuthority: null, programDataAddress: null };
  }

  // Program account layout (UpgradeableLoaderState::Program): u32 tag (2) + Pubkey programdata_address.
  if (programAccount.data.length < 36) {
    throw new RpcError(`Program account "${programId}" has unexpected data layout.`);
  }
  const programDataAddress = base58Encode(programAccount.data.slice(4, 36));

  const programDataAccount = await getAccountInfo(endpoint, programDataAddress);
  if (!programDataAccount) {
    throw new RpcError(`ProgramData account "${programDataAddress}" not found.`);
  }

  // ProgramData layout (UpgradeableLoaderState::ProgramData): u32 tag (3) + u64 slot + Option<Pubkey> upgrade_authority_address.
  const hasAuthorityByte = programDataAccount.data[12];
  let upgradeAuthority: string | null = null;
  if (hasAuthorityByte === 1) {
    upgradeAuthority = base58Encode(programDataAccount.data.slice(13, 45));
  }

  return { isUpgradeable: true, upgradeAuthority, programDataAddress };
}

/** Validate a string looks like a Solana base58 pubkey (32 bytes when decoded) before hitting an RPC. */
export function isValidPubkey(value: string): boolean {
  try {
    return base58Decode(value).length === 32;
  } catch {
    return false;
  }
}
