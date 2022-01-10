import * as hotp from "./hotp.ts";
import { IOptions } from "./mod.d.ts";

/**
 * Generates a time based one-time password for a given secret at the current time.
 *
 * @param secret Shared secret between server and client.
 * @param options
 *
 * @returns OTP token string
 */
export async function generate(
  secret: string,
  options?: IOptions,
): Promise<string> {
  const step = options?.step || 30;
  const counter = Math.floor(Date.now() / step / 1000);

  return await hotp.generate(secret, counter, options);
}

/**
 * Validates a OTP token against a given secret. By default verifies the token only at the current time window.
 *
 * A margin can be specified on the `window` option
 * @param secret Shared secret between server and client.
 * @param token OTP token to be verified
 * @param options
 * @returns Returns the step difference between the client and server. If token is not valid returns null
 */
export async function delta(
  secret: string,
  token: string,
  options?: IOptions,
): Promise<number | null> {
  const step = options?.step || 30;
  const window = options?.window || 0;
  const counter = Math.floor(Date.now() / step / 1000);

  const delta = await hotp.delta(secret, token, counter - window, {
    ...options,
    window: window + window,
  });

  return delta !== null ? delta - window : null;
}

/**
 * Verifies a time-based OTP token against a base32 encoded secret. Uses the delta function in order to validate the token.
 *
 * @param secret Shared secret between server and client.
 * @param token OTP token to be verified.
 * @param options
 *
 * @returns True if tokens matches for the given secret and current time window.
 */
export async function verify(
  secret: string,
  token: string,
  options?: IOptions,
): Promise<boolean> {
  return (await delta(secret, token, options)) !== null;
}
