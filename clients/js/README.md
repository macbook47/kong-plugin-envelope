# envelope-client (JavaScript)

Browser and Node 18+ client for Envelope v1 (`docs/SPEC.md`). One file, no dependencies.

```js
import { createSecureClient, EnvelopeError } from './envelope-client.js'

const client = createSecureClient({ baseUrl: 'https://gateway.example', apiKey: 'your-app-key' })
await client.warmUp()                       // optional: handshake at app start

const res = await client.post('/secure/api-b/transfers', { to: '0012-01-000456-50-2', amount: 1500000 })
if (res.ok) console.log(res.data)            // decrypted JSON
else console.log(res.status, res.error.code) // plain error from Kong, e.g. ENVELOPE_REPLAY
```

| Method | Notes |
|---|---|
| `get(path)` | No body; response is decrypted |
| `post/put/patch(path, body)` | `body` is an object (sent as JSON) or a JSON string (sent byte for byte) |
| `delete(path, body?)` | Sends an empty envelope when there is no body, for replay protection |
| `warmUp()` | Opens the session ahead of the first call |
| `reset()` | Drops the session (for example at logout) |

**Behavior from the spec:** keys are non-extractable; concurrent calls share one handshake; the session renews 30 seconds before expiry; the only automatic retry is after `401 ENVELOPE_SESSION`; a plain or tampered response on an encrypted route throws `EnvelopeError` instead of being returned.

**Inspection:** each result carries `wire.request`, `wire.response` (exactly what travelled) and `plain` (before encryption and after decryption), used by the kong-poc payload inspector.

## Tests

```bash
node clients/js/test/sdk.test.mjs
```

Runs 13 tests against a spec-following stand-in gateway (`test/mock-gateway.mjs`). The Kong plugin itself is tested in `tests/`.
