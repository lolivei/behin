# Behin 🦕

> One-time password lib for [Deno](http://deno.land), based on [Speakeasy](https://www.npmjs.com/package/speakeasy).

## Usage
```typescript
import Behin from "https://deno.land/x/behin/mod.ts";

// Generate a Base32 encoded secret.
const secret = Behin.generateSecret();

// Generate one-time token for a given secret
const token = Behin.totp.generate(secret);

// Verify a time base OTP token
const isValid = Behin.totp.verify(secret, token);
```

## API

### IOptions

### TOTP
Time-based one-time password

#### Behin.totp.generate(secret: string, options?: IOptions): string
#### Behin.totp.verify(secret: string, token:string, options?: IOptions): boolean
#### Behin.totp.delta(secret: string, token:string, options?: IOptions): number | null

### HOTP
HMAC-based one-time password
#### Behin.hotp.generate(secret: string, counter: number, options?: IOptions): string
#### Behin.hotp.verify(secret: string, token:string, counter: number, options?: IOptions): boolean
#### Behin.hotp.delta(secret: string, token:string, counter: number, options?: IOptions): number | null

### Secrets
#### Behin.generateSecret(size?: number): string
