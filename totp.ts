import * as hotp from './hotp.ts'
import IOptions from "./mod.d.ts";

export function generate(secret: string, options?: IOptions): string {
  const step = options?.step || 30;
  const counter = Math.floor(Date.now() / step / 1000);
  
  return hotp.generate(secret, counter, options);
}

export function delta(secret: string, token: string, options?: IOptions) {
  const step = options?.step || 30;
  const window = options?.window || 0;
  const counter = Math.floor(Date.now() / step / 1000);

  const delta = hotp.delta(secret, token, counter - window, {
    ...options,
    window: window + window
  });

  return delta !== null ? delta - window : null;
}

export function verify(secret: string, token: string, options?: IOptions) {
  return delta(secret, token, options) !== null;
}