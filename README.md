# kong-plugin-envelope

A Kong Gateway plugin that encrypts JSON request and response bodies between a client and Kong, on top of HTTPS. Upstream APIs in any language keep receiving and returning plain JSON, with no code change.

**Status:** proof of concept, version 0.1.0, built for Kong Gateway OSS 3.9.

## How it works

1. **Handshake:** the client and Kong exchange ECDH P-256 public keys and each derive the same AES-256 session key (HKDF-SHA256). The key never crosses the network. Each session belongs to the Kong consumer that opened it.
2. **Request:** the client encrypts the body with AES-256-GCM, bound to the method, path, session, sequence number and timestamp. Kong checks the session, owner, integrity and replay rules, then forwards the original bytes to the API.
3. **Response:** Kong encrypts the API's response body before sending it back.

Full details: [`docs/SPEC.md`](docs/SPEC.md).

## Repository layout

| Path | Contents |
|---|---|
| `kong/plugins/envelope/` | The plugin: `handler.lua`, `schema.lua`, `crypto.lua` |
| `tests/` | Offline tests (24) with a simulated Kong 3.9 PDK |
| `docs/SPEC.md` | Envelope v1 specification |
| `examples/kong-poc/` | Setup script and smoke test for the kong-poc lab stack |
| `clients/` | Client SDKs (JavaScript in Phase 4, Go in Phase 6) |
| `kong-plugin-envelope-0.1.0-1.rockspec` | LuaRocks package definition for building Kong images |

## Install on Kong

**Lab (Docker, mounted):** place this repository next to `kong-poc` and merge `examples/kong-poc/docker-compose.kong-snippet.yml` into the `kong` service. Then:

```bash
docker compose up -d
KONG_AUTH='admin:YOUR_PASSWORD' ./examples/kong-poc/envelope-setup.sh   # run from kong-poc, adjust the path
```

**Production direction:** build a custom Kong image and install the plugin with LuaRocks from the rockspec, instead of mounting files.

Required Kong settings:

| Setting | Value |
|---|---|
| `KONG_PLUGINS` | `bundled,envelope` |
| `KONG_NGINX_HTTP_LUA_SHARED_DICT` | `envelope_sessions 64m` |
| `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE` | at least the largest envelope size (for example `2m`) |

Attach per route, after an auth plugin: `cors` → `key-auth` (or another auth plugin) → `envelope`. The handshake route uses `mode = handshake`; protected routes use `mode = protect`.

## Run the tests

Needs LuaJIT, OpenSSL 3 and lua-cjson. The first run downloads lua-resty-openssl 1.5.1, the version bundled with Kong 3.9.

```bash
# macOS with Homebrew
brew install luajit openssl@3 luarocks
luarocks --lua-version 5.1 install lua-cjson
OPENSSL_CRYPTO_LIB=$(brew --prefix openssl@3)/lib/libcrypto.dylib \
OPENSSL_SSL_LIB=$(brew --prefix openssl@3)/lib/libssl.dylib \
./tests/run.sh
```

Expected: `24 passed, 0 failed`. The tests cover the handshake, byte-exact forwarding, response encryption, replay, stale timestamps, wrong owner, tampering, path swapping, size limits, and Kong's own responses staying plain.

The smoke test in `examples/kong-poc/` checks the plugin against a running Kong.

## Security notes

- Protects bodies from anyone between the client and Kong, including where TLS ends early. It does not protect against a compromised client device.
- Query strings and headers stay plain: keep sensitive data in the body.
- Kong holds plaintext after decryption: do not log bodies on enveloped routes.
- Open items before production (multi-node sessions, signing key, user-level owner, sizing): `docs/SPEC.md` section 11.

## Ownership

Internal proof of concept. Confirm ownership and licensing with the owning organization before sharing outside it; the rockspec license field is a placeholder.
