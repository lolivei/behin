# Behin 🦕

> One-time password lib for Deno, based on [Speakeasy](https://www.npmjs.com/package/speakeasy).

## Usage
```typescript
import Behin from "./mod.ts";

// Generate secret.
const secret = Behin.generateSecret({ bytes: 256 });
const token = Behin.otp.generate(secret);

// Verify an OTP token
const isValid = Behin.otp.verify(secret, token);
```


## API

### totp

### hotp

### Generating a base32 secret