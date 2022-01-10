export interface IOptions {
  /**
   * Time step in seconds
   *
   * **Default:** 30
   */
  step?: number;
  /**
   * Margin allowed.
   * For instance, if window = 1, validation function will allow tokens from 1 step before and 1 step after the current time.
   *
   * **Default:** 0
   */
  window?: number;
  /**
   * Length of the generated token.
   *
   * **Default:** 6
   */
  digits?: number;
  /**
   * Hash algorithm (sha1, sha256, sha512)
   *
   * **Default:** sha1
   */
  alg?: string;
}
