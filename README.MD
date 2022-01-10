# Behin 🦕

> One-time password lib for [Deno](http://deno.land), based on
> [Speakeasy](https://www.npmjs.com/package/speakeasy).

## Usage

```ts
import Behin from "https://deno.land/x/behin/mod.ts";

// Generate a Base32 encoded secret.
const secret = Behin.generateSecret();

// Generate one-time token for a given secret
const token = await Behin.totp.generate(secret);

// Verify a time base OTP token
const isValid = await Behin.totp.verify(secret, token);
```
