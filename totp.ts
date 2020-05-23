import * as hotp from './hotp.ts';
import IOptions from "./mod.d.ts";

/**
 * 
 * @param secret 
 * @param options 
 */
export function generate(secret: string, options?: IOptions): string {
  const step = options?.step || 30;
  const counter = Math.floor(Date.now() / step / 1000);
  
  return hotp.generate(secret, counter, options);
}

/**
 * @
 * @param secret - private key 
 * @param token - OTP 
 * @param options 
 * @returns the
 */
export function delta(secret: string, token: string, options?: IOptions): number | null {
  const step = options?.step || 30;
  const window = options?.window || 0;
  const counter = Math.floor(Date.now() / step / 1000);

  const delta = hotp.delta(secret, token, counter - window, {
    ...options,
    window: window + window,
  });

  return delta !== null ? delta - window : null;
}

/**
 * 
 * @param secret 
 * @param token 
 * @param options 
 */
export function verify(secret: string, token: string, options?: IOptions): boolean {
  return delta(secret, token, options) !== null;
}