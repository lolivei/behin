# Behin 🦕

> One-time password lib for Deno 🦕, based on [Speakeasy](https://www.npmjs.com/package/speakeasy).

## Usage
```typescript
import Behin from "./mod.ts";

// Generate a Base32 encoded secret.
const secret = Behin.generateSecret();
const token = Behin.totp.generate(secret);

// Verify a time base OTP token
const isValid = Behin.totp.verify(secret, token);
```

## API

### totp

### hotp

### Generating a base32 secret