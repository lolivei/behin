import * as hotp from './hotp.ts';
import * as totp from './totp.ts';
import { generateSecret } from './secrets.ts';

const Behin = {
  totp,
  hotp,
  generateSecret,
};

export default Behin;
