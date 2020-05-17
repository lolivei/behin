import { decode, encode } from "https://deno.land/std/encoding/base32.ts";
import { hmac } from "https://denopkg.com/chiefbiiko/hmac@v1.0.2/mod.ts";

enum Alg {
  SHA1 = 'sha1',
  SHA256 = 'sha256',
  SHA512 = 'sha512',
}

interface IOptions {
  step?: number
  window?: number
  digits?: number
  alg?: string
}

function padBase32(secret: string): string {
  const max = Math.ceil(secret.length / 8) * 8
  return secret.padEnd(max, '=').toUpperCase()
}

function digestOptions(secret: string, counter: number, options?: IOptions): Uint8Array {
  const secretBytes = decode(padBase32(secret))
  const alg = options?.alg || Alg.SHA1

  let counterBytes = new Uint8Array(8);
  let tmp = counter;
  for (let i = 0; i < 8; i++) {
    counterBytes[7 - i] = tmp & 0xff;
    tmp = tmp >> 8;
  }

  return hmac(alg, secretBytes, counterBytes) as Uint8Array;
}

const hotp = {
  generate: function (secret: string, counter: number, options?: IOptions): string {
    const digits = options?.digits || 6

    if (!secret) throw new Error("Behin: Missing secret");
    if (!counter) throw new Error("Behin: Missing counter");

    const digest = digestOptions(secret, counter, options)
    
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
  },
  delta: function (secret: string, token: string, counter: number, options?: IOptions): number | null {
    const digits = options?.digits || 6;
    const window = options?.window || 0;

    if (!token) throw new Error("Behin: Missing token");
    if (token.length !== digits) throw new Error("Behin: Wrong token length");
    

    for (let i = counter; i <= counter + window; i++) {
      if (hotp.generate(secret, i, options) === token) {
        return i - counter
      }
    }

    return null
  },
  verify: function (secret: string, token: string, counter: number, options?: IOptions) {
    return hotp.delta(secret, token, counter, options) !== null
  }
}

const totp = {
  generate: function (secret: string, options?: IOptions): string {
    const step = options?.step || 30;
    const counter = Math.floor(Date.now() / step / 1000);
    
    return hotp.generate(secret, counter, options);
  },
  delta: function (secret: string, token: string, options?: IOptions) {
    const step = options?.step || 30;
    const window = options?.window || 0;
    const counter = Math.floor(Date.now() / step / 1000);

    const delta = hotp.delta(secret, token, counter - window, {
      ...options,
      window: window + window
    })

    return delta !== null ? delta - window : null
  },
  verify: function (secret: string, token: string, options?: IOptions) {
    return totp.delta(secret, token, options) !== null
  }
}

function generateSecret(length?: number): string {
  const secretLength = length || 32;
  var bytes = crypto.getRandomValues(new Uint8Array(secretLength));
  return encode(bytes).replace(/=/g, '')
}

export {
  totp,
  hotp,
  generateSecret,
}
