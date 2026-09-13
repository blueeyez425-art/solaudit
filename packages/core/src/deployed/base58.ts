/**
 * Minimal, dependency-free base58 encoder/decoder (Bitcoin/Solana alphabet),
 * implemented with the standard "base-x" algorithm. Solana pubkeys are 32 raw
 * bytes displayed as base58 — this keeps the package's zero-dependency
 * guarantee intact instead of pulling in the `bs58` package.
 */
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  const size = Math.ceil(((bytes.length - zeros) * 138) / 100) + 1; // log(256)/log(58) ≈ 1.38
  const b58 = new Uint8Array(size);

  let length = 0;
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    let j = 0;
    for (let it = size - 1; (carry !== 0 || j < length) && it >= 0; it--, j++) {
      carry += 256 * b58[it];
      b58[it] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    length = j;
  }

  let it = size - length;
  while (it < size && b58[it] === 0) it++;

  let result = "1".repeat(zeros);
  for (; it < size; it++) result += ALPHABET[b58[it]];
  return result;
}

export function base58Decode(input: string): Uint8Array {
  if (input.length === 0) return new Uint8Array();

  let zeros = 0;
  while (zeros < input.length && input[zeros] === "1") zeros++;

  const size = Math.ceil(((input.length - zeros) * Math.log(58)) / Math.log(256)) + 1;
  const b256 = new Uint8Array(size);

  let length = 0;
  for (let i = zeros; i < input.length; i++) {
    const value = ALPHABET.indexOf(input[i]);
    if (value === -1) throw new Error(`Invalid base58 character: "${input[i]}"`);

    let carry = value;
    let j = 0;
    for (let it = size - 1; (carry !== 0 || j < length) && it >= 0; it--, j++) {
      carry += 58 * b256[it];
      b256[it] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    length = j;
  }

  let it = size - length;
  while (it < size && b256[it] === 0) it++;

  const result = new Uint8Array(zeros + (size - it));
  result.fill(0, 0, zeros);
  let i = zeros;
  while (it < size) result[i++] = b256[it++];
  return result;
}
