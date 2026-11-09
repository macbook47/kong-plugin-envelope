# Envelope Encryption for Kong: Specification v1 (PoC)

Nov 9, 2026 · Faizudin Al Hamawi

## 1. Purpose and scope

Envelope v1 encrypts JSON request and response bodies between a client and Kong, so that upstream APIs in any language keep sending and receiving plain JSON with no code change. Encryption runs on top of HTTPS, never instead of it.

| Party | Responsibility |
| --- | --- |
| Client SDK | Handshake, encrypt request bodies, decrypt response bodies, renew sessions |
| Kong envelope plugin | Handshake, session store, all request checks, decrypt requests, encrypt upstream responses |
| Kong key-auth (or another auth plugin) | Identify the calling consumer before the envelope plugin runs |
| Upstream API | Nothing new: plain JSON in, plain JSON out |

**In scope for v1:** JSON request bodies on POST, PUT, PATCH and DELETE; JSON responses from upstream APIs on enveloped routes; sessions bound to Kong consumers; replay protection; size limits.

**Out of scope for v1:** query strings and headers (stay plain), non-JSON bodies, streaming, multi-node session sharing, a server signing key (field reserved), mobile SDKs.

The cryptographic profile below was verified in Phase 1 against Kong 3.9's bundled lua-resty-openssl 1.5.1 and the browser Web Crypto API: both sides derived the same session key, and tampered, moved or wrongly keyed envelopes were rejected.

## 2. Cryptographic profile

Every element uses a standard algorithm available natively in browsers (Web Crypto), Go, Java, .NET, Python and Rust, so any team can implement a client from this document.

| Element | Value |
| --- | --- |
| Key agreement | ECDH on P-256 (prime256v1), a fresh key pair on both sides for every session |
| Public key format | JWK with fields `kty`, `crv`, `x`, `y` only (`kty` = "EC", `crv` = "P-256") |
| Key derivation | HKDF-SHA256, salt = 32 random bytes chosen by Kong, info = `envelope-v1`, output 32 bytes |
| Body encryption | AES-256-GCM, 12-byte IV, 16-byte tag |
| IV rule | A new random IV for every message, from a cryptographically secure generator |
| Ciphertext layout | ciphertext followed by the 16-byte tag (the Web Crypto layout) |
| Binary encoding | Standard base64 with padding for `iv`, `ct` and `salt` (JWK fields use base64url, per JWK) |
| Text encoding | UTF-8 everywhere |
| Session ID | 32 random bytes, base64url without padding |

Clients must create the ECDH private key as non-extractable where the platform allows it (Web Crypto `extractable: false`), and must never persist it to storage.

## 3. Handshake

A client opens a session with one call to the handshake route; Kong answers directly and nothing reaches an upstream API. The route carries the same auth plugin as the enveloped routes, so every session has an owner.

**Request:** `POST /envelope/handshake`, with the client's credential (for the PoC, the `apikey` header) and `Content-Type: application/json`.

```json
{ "v": 1, "pub": { "kty": "EC", "crv": "P-256", "x": "<base64url>", "y": "<base64url>" } }
```

**Response:** `200`, with `Cache-Control: no-store`.

```json
{ "v": 1, "sid": "<session id>", "pub": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }, "salt": "<base64>", "expires_in": 900, "kid": null }
```

**Steps on Kong:**

1. Reject the call if no consumer was identified (`401 ENVELOPE_NO_CONSUMER`).
2. Parse `pub`; reject anything that is not a valid P-256 point (`400 ENVELOPE_BAD_HANDSHAKE`). This blocks invalid-curve attacks.
3. Generate a fresh P-256 key pair, compute the ECDH shared secret, then derive the session key with HKDF (section 2).
4. Generate `sid` and `salt`, store the session record, and return Kong's public key. Kong's private key and the shared secret are discarded at once.

**Steps on the client:** compute the same ECDH secret from Kong's `pub`, derive the same key with HKDF and the returned `salt`, import it as a non-extractable AES-GCM key, and keep `sid`, the key, the expiry and a sequence counter starting at 0.

**Session record (Kong):** session key, owner consumer ID, expiry time, and the sequence numbers already seen. Records expire after `expires_in` seconds (default 900).

`kid` is reserved for a future server signing key and is always `null` in v1. Clients must ignore unknown response fields so v1.x can add them.

## 4. Request envelope

Enveloped request bodies carry the exact bytes of the original JSON, so Kong forwards them byte for byte and never re-serializes them; re-serializing could round large numbers such as amounts or account numbers.

**Headers on every request to an enveloped route**, including GET:

| Header | Value |
| --- | --- |
| Credential (PoC: `apikey`) | The consumer's credential, same consumer as the handshake |
| `X-Envelope-Session` | `sid` from the handshake |
| `X-Envelope-Seq` | Positive integer, unique within the session (section 6) |
| `X-Envelope-Ts` | Client time in milliseconds since the Unix epoch |

**Body for POST, PUT, PATCH and DELETE** (`Content-Type: application/json`). Clients send an envelope on DELETE too, encrypting an empty plaintext when there is no body, so DELETE gets replay protection.

```json
{ "v": 1, "iv": "<base64, 12 bytes>", "ct": "<base64, ciphertext + tag>" }
```

**Plaintext:** the original request body as UTF-8 JSON bytes, or empty.

**Additional authenticated data (AAD):** the exact UTF-8 string below. It is not sent; both sides rebuild it, so changing the method, path, session, sequence or timestamp breaks decryption.

```
envelope-v1|req|{METHOD}|{PATH}|{sid}|{seq}|{ts}
```

Example: `envelope-v1|req|POST|/secure/api-b/transfers|Xb3…|42|1794207080407`.

**Path rule:** `{PATH}` is the request path exactly as sent, without the query string. Clients must send normalized paths: no `..` or `.` segments, no repeated slashes, no percent-encoding of unreserved characters.

**Kong after a successful decrypt:** replaces the body with the plaintext, sets `Content-Type: application/json` and the correct `Content-Length`, removes `X-Envelope-*` headers, and forwards to the upstream API. GET and HEAD requests have no body and are forwarded unchanged apart from the header removal.

## 5. Response envelope

Kong encrypts every non-empty response body that comes from the upstream API on an enveloped route; responses Kong generates itself (auth failures, envelope errors, rate limits) stay plain so clients can always read why a call failed.

**Body:** the same shape as a request envelope, with `Content-Type: application/json`.

```json
{ "v": 1, "iv": "<base64, 12 bytes>", "ct": "<base64, ciphertext + tag>" }
```

**Plaintext:** the upstream body exactly as received, any content type.

**AAD:**

```
envelope-v1|res|{METHOD}|{PATH}|{sid}|{seq}
```

`{seq}` is the request's `X-Envelope-Seq`, so a client can tell which request a response belongs to and an attacker cannot swap responses between parallel calls.

**Headers Kong sets:**

| Header | Value |
| --- | --- |
| `X-Envelope` | `1` on an encrypted response; absent otherwise |
| `X-Envelope-Content-Type` | The upstream `Content-Type`, so the client can restore it |
| `Content-Type` | `application/json` |
| `Content-Length` | Removed; the encrypted body is sent chunked after Kong buffers the full response |

**Not encrypted:** the HTTP status code and the other upstream headers. APIs must not put sensitive data in response headers. An empty upstream body (for example `204`) is returned empty, without `X-Envelope`.

**Client rule:** treat a response as encrypted only when `X-Envelope: 1` is present; otherwise read it as a plain error or empty body. Never accept a plain body as a success on an enveloped route.

## 6. Replay protection

Kong accepts each sequence number at most once per session and only within a 60-second time window, so a captured enveloped request cannot be sent again. Because `seq` and `ts` are part of the AAD, an attacker cannot change them without breaking decryption.

**Kong checks, after a successful decrypt:**

1. `X-Envelope-Ts` is within the allowed clock skew of Kong's time (default ±60 seconds), else `409 ENVELOPE_STALE`.
2. `X-Envelope-Seq` has not been seen in this session, else `409 ENVELOPE_REPLAY`. The check-and-record is atomic.
3. The session has not exceeded its sequence budget (default 100,000 requests), else `401 ENVELOPE_SESSION`, which makes the client re-handshake.

**Client rules:**

- Start `seq` at 1 for each new session and increase it by 1 per request; never reuse a value within a session.
- Requests may arrive out of order (parallel calls); Kong does not require increasing values, only unique ones.
- Keep the device clock synchronized; a clock off by more than the skew causes `ENVELOPE_STALE`.
- Retry automatically only on `401 ENVELOPE_SESSION`: re-handshake, then resend once with a new `seq`. These failures happen before the request reaches the API, so the retry cannot duplicate a transaction. Never auto-retry any other error.

**Coverage:** the guarantee applies to POST, PUT, PATCH and DELETE, whose `seq` and `ts` are authenticated. GET and HEAD send the same headers and Kong applies the same checks, but those headers are not authenticated, so an attacker could replay a GET with a new `seq`. The impact is limited: the response is encrypted with the client's session key and stays unreadable to the attacker. APIs must keep GET free of side effects.

## 7. Size limits and files

Enveloped bodies are limited to 1 MB of plaintext per route by default, because Kong must hold the whole body in memory and a file sent as base64 inside an envelope grows to 1.78 times its size on the wire. Encryption speed is not the constraint: Phase 1 measured about 1 ms per MB.

**Requests:** Kong compares the declared `Content-Length` with the route limit before reading the body and rejects oversize requests with `413 ENVELOPE_TOO_LARGE`. Requests without a declared length are read only up to the limit. The limit is set per route through the reviewed config process.

**Responses (fail closed):** if an upstream response is larger than the route limit, Kong returns `502 ENVELOPE_RESPONSE_TOO_LARGE` and never sends the body unencrypted. APIs on enveloped routes must paginate large results.

**Kong configuration:** the request body buffer (`nginx_http_client_body_buffer_size`) should be at least the largest envelope size, so bodies stay in memory. Kong 3.9 can still read a body that spilled to a temporary file, up to the route limit, but more slowly.

**Files above the limit** go through a separate path instead of the envelope:

1. The client asks an enveloped API for an upload slot; the API returns a short-lived pre-signed upload URL for object storage.
2. The client uploads the file directly to object storage over HTTPS.
3. The client sends an enveloped request carrying the file's metadata and its SHA-256 hash.
4. The API checks that the stored file matches the hash before using it.

This keeps large files out of Kong's memory while every file stays tied to an authenticated, encrypted, tamper-proof request. Chunked encryption for streaming is a possible v2 item.

## 8. Errors

Every envelope error is a plain JSON body `{ "code": "ENVELOPE_…", "message": "…" }`, returned before the request reaches the API, so no error below can cause a duplicate transaction. Messages stay generic; details go to Kong's log only.

| Status | Code | Meaning | Client action |
| --- | --- | --- | --- |
| 400 | `ENVELOPE_BAD_HANDSHAKE` | Handshake body or public key invalid | Fix the client; do not retry |
| 401 | `ENVELOPE_NO_CONSUMER` | No consumer identified (normally the auth plugin answers first) | Check the credential; do not retry |
| 401 | `ENVELOPE_SESSION` | Session missing, unknown, expired or over its sequence budget | Re-handshake, then retry once |
| 403 | `ENVELOPE_OWNER` | Session belongs to a different consumer | Do not retry; handshake with your own credential |
| 400 | `ENVELOPE_MISSING` | Envelope or `X-Envelope-*` header missing or malformed | Fix the client; do not retry |
| 400 | `ENVELOPE_BAD` | Decryption failed: tampered body, wrong key, wrong AAD or unknown version | Do not retry; treat as possible tampering |
| 409 | `ENVELOPE_STALE` | `X-Envelope-Ts` outside the allowed skew | Check the device clock; the app may resend with a new `seq` and `ts` |
| 409 | `ENVELOPE_REPLAY` | `X-Envelope-Seq` already used in this session | Do not retry; client bug or replay attempt |
| 413 | `ENVELOPE_TOO_LARGE` | Body over the route limit | Use the file path (section 7) |
| 415 | `ENVELOPE_UNSUPPORTED` | Enveloped method sent without `Content-Type: application/json` | Fix the client |
| 502 | `ENVELOPE_RESPONSE_TOO_LARGE` | Upstream response over the route limit; not sent | Fix the API: paginate |

Rejections already appear as 4xx counts per consumer on the Traffic page; counts per envelope code are an open item (section 11).

## 9. Plugin configuration

The plugin is named `envelope`, runs with priority 1000, and is attached per route. Priority 1000 places it after CORS (2000) and key-auth (1250), so preflight requests and the consumer are settled before it runs, and before rate limiting (910).

| Field | Default | Meaning |
| --- | --- | --- |
| `mode` | `protect` | `handshake` on the handshake route; `protect` on enveloped routes |
| `session_ttl` | 900 | Session lifetime in seconds |
| `clock_skew` | 60 | Allowed difference between `X-Envelope-Ts` and Kong's clock, in seconds |
| `max_seq_per_session` | 100000 | Requests allowed per session before a re-handshake |
| `max_body_size` | 1048576 | Plaintext limit in bytes for request and response bodies |
| `require_consumer` | true | Reject calls without an identified consumer |
| `enveloped_methods` | POST, PUT, PATCH, DELETE | Methods that must carry an envelope |

**Gateway settings needed once:**

| Setting | Value | Why |
| --- | --- | --- |
| `KONG_PLUGINS` | `bundled,envelope` | Loads the custom plugin |
| `KONG_NGINX_HTTP_LUA_SHARED_DICT` | `envelope_sessions 64m` | Session store shared by all Kong workers on a node |
| `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE` | At least the largest `max_body_size` | Keeps bodies in memory (section 7) |

**CORS on enveloped and handshake routes:** allow request headers `apikey`, `X-Envelope-Session`, `X-Envelope-Seq` and `X-Envelope-Ts`; expose `X-Envelope` and `X-Envelope-Content-Type`.

The 64 MB session store size is a starting estimate for the PoC, not a measured figure; Phase 7 will measure memory per session and per stored sequence number.

## 10. Security considerations and limits

Envelope v1 protects request and response bodies from anyone between the client and Kong, including at points where TLS is terminated early; it does not protect against a compromised client device or browser.

**What it protects against:**

- Reading bodies at intermediaries that terminate TLS before Kong (load balancers, WAFs, proxies) and in their logs.
- Tampering with a body, or moving it to another method, path or session: AES-GCM with the AAD rejects it.
- Replaying a captured POST, PUT, PATCH or DELETE (section 6).
- Using one consumer's session with another consumer's credential (`ENVELOPE_OWNER`).

**What it does not protect against:**

- A user or malware controlling the client: whoever runs the SDK can encrypt anything. Server-side validation and authorization stay mandatory.
- Data in URLs, query strings or headers, which stay plain. Design rule: no sensitive data outside the body.
- Gateway impersonation if TLS itself is broken: v1 has no server signing key (`kid` is reserved).
- Plaintext inside Kong: after decryption Kong holds the plain body, so logging plugins on enveloped routes must not log bodies.

**Browser credential:** an API key in a browser app identifies the app, not the user, and is readable by anyone. For production, sessions should be bound to the user's login token (for example a JWT checked by Kong's `jwt` plugin); only the "consumer identified" step changes.

**Performance (Phase 1, test environment, not inside Kong):** handshake about 0.9 ms of CPU; encryption about 2 µs per 1 KB and about 1 ms per 1 MB. Handshakes dominate CPU cost, so session lifetime is a capacity setting. Phase 7 replaces these with end-to-end measurements.

## 11. Open items for production

These items are outside the PoC but must be decided before production use.

| Item | Why it matters | Direction |
| --- | --- | --- |
| Multi-node session store | Shared memory is per Kong node; a client hitting another node gets `ENVELOPE_SESSION` | Redis with the same record format, or sticky routing |
| Server signing key | Proves the handshake came from Kong if TLS is compromised | Kong Keys / Key Sets, `kid` in the handshake, scheduled rotation with overlap |
| User-level session owner | An app API key does not identify the user | Bind sessions to the user's login token (JWT) |
| Per-code rejection metrics | Spotting tampering or client bugs per consumer | Plugin-level counters exported to Prometheus |
| Chunked encryption | Files and large responses cannot stream today | v2 design, if the file path in section 7 is not enough |
| Mobile and partner SDKs | Only the JavaScript SDK is built in the PoC | Kotlin, Swift, Java and C# from this spec, with shared test vectors |
| Gateway sizing | Handshake and buffering cost CPU and memory | Use Phase 7 results; set session lifetime and body limits per route |
| Plugin ownership | A custom plugin is code BRI must maintain and security-review | Named owning team, SDLC, and penetration test before go-live |
