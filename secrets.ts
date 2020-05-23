import { encode } from "./deps.ts";

export function generateSecret(size?: number): string {
  const secretLength = size || 32;
  var bytes = crypto.getRandomValues(new Uint8Array(secretLength));
  return encode(bytes).replace(/=/g, "");
}