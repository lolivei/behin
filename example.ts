import Behin from "./mod.ts";

// Generate a Base32 encoded secret.
const secret = Behin.generateSecret();

// Generate one-time token for a given secret
const token = Behin.totp.generate(secret);

// Verify a time base OTP token
const isValid = Behin.totp.verify(secret, token);