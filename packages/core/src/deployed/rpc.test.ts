import { afterEach, describe, expect, test } from "bun:test";
import { base58Decode, base58Encode } from "./base58";
import { BPF_LOADER_UPGRADEABLE, getUpgradeAuthority, isValidPubkey, RpcError } from "./rpc";

const ENDPOINT = "https://fake-rpc.test";

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/** Build fake UpgradeableLoaderState::Program account data: u32 tag(2) + Pubkey programDataAddress. */
function buildProgramAccountData(programDataAddress: string): Uint8Array {
  const out = new Uint8Array(36);
  new DataView(out.buffer).setUint32(0, 2, true);
  out.set(base58Decode(programDataAddress), 4);
  return out;
}

/** Build fake UpgradeableLoaderState::ProgramData data: u32 tag(3) + u64 slot + Option<Pubkey> authority. */
function buildProgramDataAccountData(authority: string | null): Uint8Array {
  const out = new Uint8Array(authority ? 45 : 13);
  const view = new DataView(out.buffer);
  view.setUint32(0, 3, true);
  // slot (u64) left as zero
  out[12] = authority ? 1 : 0;
  if (authority) out.set(base58Decode(authority), 13);
  return out;
}

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
});

describe("isValidPubkey", () => {
  test("accepts a valid 32-byte base58 pubkey", () => {
    expect(isValidPubkey("11111111111111111111111111111111")).toBe(true);
  });

  test("rejects garbage input", () => {
    expect(isValidPubkey("not-a-pubkey")).toBe(false);
    expect(isValidPubkey("")).toBe(false);
  });
});

describe("getUpgradeAuthority", () => {
  test("reports an active upgrade authority", async () => {
    const programId = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const programDataAddress = "11111111111111111111111111111112";
    const authority = "So11111111111111111111111111111111111111112";

    let call = 0;
    global.fetch = (async () => {
      call++;
      if (call === 1) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            result: {
              value: {
                owner: BPF_LOADER_UPGRADEABLE,
                data: [b64(buildProgramAccountData(programDataAddress)), "base64"],
                executable: true,
                lamports: 1,
              },
            },
          })
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: {
              owner: "BPFLoaderUpgradeab1e11111111111111111111111",
              data: [b64(buildProgramDataAccountData(authority)), "base64"],
              executable: false,
              lamports: 1,
            },
          },
        })
      );
    }) as typeof fetch;

    const result = await getUpgradeAuthority(ENDPOINT, programId);
    expect(result.isUpgradeable).toBe(true);
    expect(result.upgradeAuthority).toBe(authority);
  });

  test("reports a revoked upgrade authority as immutable", async () => {
    const programDataAddress = "11111111111111111111111111111112";

    let call = 0;
    global.fetch = (async () => {
      call++;
      if (call === 1) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            result: {
              value: {
                owner: BPF_LOADER_UPGRADEABLE,
                data: [b64(buildProgramAccountData(programDataAddress)), "base64"],
                executable: true,
                lamports: 1,
              },
            },
          })
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: {
              owner: BPF_LOADER_UPGRADEABLE,
              data: [b64(buildProgramDataAccountData(null)), "base64"],
              executable: false,
              lamports: 1,
            },
          },
        })
      );
    }) as typeof fetch;

    const result = await getUpgradeAuthority(ENDPOINT, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    expect(result.isUpgradeable).toBe(true);
    expect(result.upgradeAuthority).toBeNull();
  });

  test("reports non-upgradeable programs correctly", async () => {
    global.fetch = (async () =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            value: {
              owner: "BPFLoader2111111111111111111111111111111111",
              data: [b64(new Uint8Array(4)), "base64"],
              executable: true,
              lamports: 1,
            },
          },
        })
      )) as typeof fetch;

    const result = await getUpgradeAuthority(ENDPOINT, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    expect(result.isUpgradeable).toBe(false);
    expect(result.upgradeAuthority).toBeNull();
  });

  test("throws RpcError when the account does not exist", async () => {
    global.fetch = (async () =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { value: null } }))) as typeof fetch;

    await expect(getUpgradeAuthority(ENDPOINT, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")).rejects.toThrow(
      RpcError
    );
  });
});
