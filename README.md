# webauthn-parser

Set of utils for parsing WebAuthn data.

## Usage

```ts
import { parseClient } from "webauthn-parser";

// clientDataJSON comes from credential.response.clientDataJSON
const collectedClientData = parseClient(clientDataJSON);
console.log(collectedClientData);
```

```ts
import { parseClient } from "webauthn-parser";

// authenticatorData comes from credential.response.getAuthenticatorData()
const authenticatorDataResult = parseAuthenticatorData(authenticatorData);
console.log(authenticatorDataResult);
```

## Development

To install dependencies:

```bash
bun install
```

To test:

```bash
bun run test
```

To build:

```bash
bun run build
```
