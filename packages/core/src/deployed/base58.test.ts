import { describe, expect, test } from "bun:test";
import { base58Decode, base58Encode } from "./base58";

describe("base58", () => {
  test("round-trips a known Solana pubkey", () => {
    // The system program ID, a well-known constant.
    const pubkey = "11111111111111111111111111111111";
    const decoded = base58Decode(pubkey);
    expect(decoded.length).toBe(32);
    expect(base58Encode(decoded)).toBe(pubkey);
  });

  test("round-trips a non-trivial pubkey", () => {
    const pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const decoded = base58Decode(pubkey);
    expect(base58Encode(decoded)).toBe(pubkey);
  });

  test("round-trips arbitrary bytes with leading zero byte", () => {
    const bytes = new Uint8Array(32);
    bytes[0] = 0;
    bytes[1] = 1;
    bytes[31] = 255;
    const encoded = base58Encode(bytes);
    const decoded = base58Decode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });

  test("rejects invalid characters", () => {
    expect(() => base58Decode("0OIl")).toThrow();
  });
});
