# Behin 🦕

> One-time password lib for [Deno](http://deno.land), based on [Speakeasy](https://www.npmjs.com/package/speakeasy).

## Usage
```ts
import Behin from "https://deno.land/x/behin/mod.ts";

// Generate a Base32 encoded secret.
const secret = Behin.generateSecret();

// Generate one-time token for a given secret
const token = Behin.totp.generate(secret);

// Verify a time base OTP token
const isValid = Behin.totp.verify(secret, token);
```

## API

### TOTP
Time-based one-time password

```ts
Behin.totp.generate(secret: string, options?: IOptions): string
```
Generates a one-time password for a given secret. 

**returns** `string` - One-time password
| Param | Type | Default | Description |
| ------ | ------ | ------ | ------ |
| **secret** | `string` |  |  Base32 encoded shared key |
| **options** | `object` |  | 
| **options.alg** | `string` | sha1 | Hash algorithm (sha1, sha256, sha512) |
| **options.digits** |` number` | 6 | Length of the generated token |
| **options.step** | `number` | 30 | Time step in seconds |

-------
```ts
Behin.totp.verify(secret: string, token: string, options?: IOptions): boolean
```
Verify an OTP token against a base32 encoded secret. Uses the delta function in order to validate the token.

**returns** `boolean` - True if tokens matches for the given secret and window.
| Param | Type | Default | Description |
| ------ | ------ | ------ | ------ |
| **secret** | `string` |  |  Base32 encoded shared key |
| **token** | `string` |  |  OTP token to validate |
| **options** | `object` |  | 
| **options.alg** | `string` | sha1 | Hash algorithm (sha1, sha256, sha512) |
| **options.window** | `number` | 0 | Margin allowed. For instance, if window = 1, validation function will allow tokens from 1 step before and 1 step after the current time |
| **options.digits** |` number` | 6 | Length of the generated token |
| **options.step** | `number` | 30 | Time step in seconds |


--------
```ts
Behin.totp.delta(secret: string, token: string, options?: IOptions): number | null
```
Validates a OTP token against a given secret. By default verifies the token only at the current time window. 

**returns** `number | null` - Returns the step difference between the client and server. If token is not valid returns null 
| Param | Type | Default | Description |
| ------ | ------ | ------ | ------ |
| **secret** | `string` |  |  Base32 encoded shared key |
| **token** | `string` |  |  OTP token to validate |
| **options** | `object` |  | 
| **options.alg** | `string` | sha1 | Hash algorithm (sha1, sha256, sha512)
| **options.window** | `number` | 0 | Margin allowed. For instance, if window = 1, validation function will allow tokens from 1 step before and 1 step after the current time |
| **options.digits** |` number` | 6 | Length of the generated token
| **options.step** | `number` | 30 | Time step in seconds

### HOTP
HMAC-based one-time password
```ts
Behin.hotp.generate(secret: string, counter: number, options?: IOptions): string
```
```ts
Behin.hotp.verify(secret: string, token: string, counter: number, options?: IOptions): boolean
```
```ts
Behin.hotp.delta(secret: string, token: string, counter: number, options?: IOptions): number | null
```

### Secrets
```ts
Behin.generateSecret(size?: number): string
```
Generates a base32 encoded random secret.

**returns** `string` - Base32 encoded random secret.
| Param | Type | Default | Description |
| ------ | ------ | ------ | ------ |
| **size** | `number` | 32 | Byte size of generated secret

