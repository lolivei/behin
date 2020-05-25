import { decode, hmac } from "./deps.ts";
import { IOptions } from "./mod.d.ts";

export enum Alg {
  SHA1 = "sha1",
  SHA256 = "sha256",
  SHA512 = "sha512",
}

function padBase32(secret: string): string {
  const max = Math.ceil(secret.length / 8) * 8;
  return secret.padEnd(max, "=").toUpperCase();
}

function digestOptions(secret: string, counter: number, options?: IOptions): Uint8Array {
  const secretBytes = decode(padBase32(secret));
  const alg = options?.alg || Alg.SHA1;

  let counterBytes = new Uint8Array(8);
  let tmp = counter;
  for (let i = 0; i < 8; i++) {
    counterBytes[7 - i] = tmp & 0xff;
    tmp = tmp >> 8;
  }

  return hmac(alg, secretBytes, counterBytes) as Uint8Array;
}

/**
 * Generates a HMAC-based one-time password. 
 * Specify the key and counter, and receive the OTP for the given counter position.
 * 
 * @param secret Shared secret between server and client.
 * @param counter Counter value.
 * @param options 
 * @returns OTP token
 */
export function generate(secret: string, counter: number, options?: IOptions): string {
  const digits = options?.digits || 6;

  if (!secret) throw new Error("Behin: Missing secret");
  if (!counter) throw new Error("Behin: Missing counter");

  const digest = digestOptions(secret, counter, options);
  
  // calculate binary code (RFC4226 5.4)
  var offset = digest[digest.length - 1] & 0xf;
  const code = (digest[offset] & 0x7f) << 24 |
    (digest[offset + 1] & 0xff) << 16 |
    (digest[offset + 2] & 0xff) << 8 |
    (digest[offset + 3] & 0xff);

  // left-pad code
  const lfCode = new Array(digits + 1).join('0') + code.toString(10);

  // return length number off digits
  return lfCode.substr(-digits);
}

/**
 * Validates a OTP token against a given secret. By default verifies the token only at the given counter. 
 * 
 * A margin can be specified on the `window` option
 * @param secret Shared secret between server and client.
 * @param token OTP token to be verified
 * @param counter Counter value.
 * @param options 
 * @returns Returns the counter difference between the client and server. If token is not valid returns null 
 */
export function delta(secret: string, token: string, counter: number, options?: IOptions): number | null {
  const digits = options?.digits || 6;
  const window = options?.window || 0;

  if (!token) throw new Error("Behin: Missing token");
  if (token.length !== digits) throw new Error("Behin: Wrong token length");
  

  for (let i = counter; i <= counter + window; i++) {
    if (generate(secret, i, options) === token) {
      return i - counter;
    }
  }

  return null;
}

 /** 
  * Verifies an OTP token against a base32 encoded secret. Uses the delta function in order to validate the token.
  * 
  * @param secret Shared secret between server and client.
  * @param token OTP token to be verified.
  * @param counter Counter value.
  * @param options 
  * 
  * @returns True if tokens matches for the given secret and counter for a given window.
  */
export function verify(secret: string, token: string, counter: number, options?: IOptions) {
  return delta(secret, token, counter, options) !== null;
}

