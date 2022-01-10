import * as hotp from "./hotp.ts";
import * as totp from "./totp.ts";
import { generateSecret } from "./secrets.ts";

const Behin = {
  /** Time-based one-time password */
  totp,
  /** HMAC-based one-time password */
  hotp,
  generateSecret,
};

export default Behin;
