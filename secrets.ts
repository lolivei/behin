import { encode } from "./deps.ts";

export function generateSecret(length?: number): string {
  const secretLength = length || 32;
  var bytes = crypto.getRandomValues(new Uint8Array(secretLength));
  return encode(bytes).replace(/=/g, "");
}