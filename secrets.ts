import { encode } from "./deps.ts";

/**
 * Generates a base32 enconded secret.
 * 
 * @param size - Byte size of generated secret.
 * @returns base32 encoded secret
 */
export function generateSecret(size?: number): string {
  const secretLength = size || 32;
  var bytes = crypto.getRandomValues(new Uint8Array(secretLength));
  return encode(bytes).replace(/=/g, "");
}