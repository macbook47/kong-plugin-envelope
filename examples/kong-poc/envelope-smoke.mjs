// Phase 3 smoke test: a minimal spec-following client (Web Crypto, same API as browsers).
// Run inside the Docker network so it reaches Kong as http://kong:8000.
const BASE = process.env.BASE || 'http://kong:8000'
const KEY = process.env.APIKEY || 'poc-ui-key'
const OTHER_KEY = process.env.OTHER_APIKEY || 'team-y-key'
const { subtle } = globalThis.crypto
const enc = new TextEncoder()
const dec = new TextDecoder()
const b64 = (buf) => Buffer.from(buf).toString('base64')
const unb64 = (s) => Buffer.from(s, 'base64')

async function handshake(apikey) {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const jwk = await subtle.exportKey('jwk', kp.publicKey)
  const res = await fetch(`${BASE}/envelope/handshake`, {
    method: 'POST',
    headers: { apikey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ v: 1, pub: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }),
  })
  const body = await res.json()
  if (res.status !== 200) throw new Error(`handshake ${res.status} ${JSON.stringify(body)}`)
  const serverPub = await subtle.importKey('jwk', body.pub, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const secret = await subtle.deriveBits({ name: 'ECDH', public: serverPub }, kp.privateKey, 256)
  const hkdf = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey'])
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: unb64(body.salt), info: enc.encode('envelope-v1') },
    hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])   // non-extractable
  return { apikey, sid: body.sid, key, seq: 0, expiresIn: body.expires_in }
}

// One call following spec sections 4 and 5. opts lets tests break the rules on purpose.
async function call(s, method, pathWithQuery, bodyObj, opts = {}) {
  const path = pathWithQuery.split('?')[0]
  const seq = opts.seq ?? ++s.seq
  const ts = String(opts.ts ?? Date.now())
  const headers = { apikey: opts.apikey ?? s.apikey, 'X-Envelope-Session': opts.sid ?? s.sid,
                    'X-Envelope-Seq': String(seq), 'X-Envelope-Ts': ts }
  let body
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const aad = enc.encode(`envelope-v1|req|${method}|${path}|${s.sid}|${seq}|${ts}`)
    const plain = bodyObj === undefined ? new Uint8Array() : enc.encode(JSON.stringify(bodyObj))
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, s.key, plain)
    body = JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) })
    headers['Content-Type'] = 'application/json'
  }
  const res = await fetch(BASE + pathWithQuery, { method, headers, body })
  const raw = await res.text()
  const out = { status: res.status, raw, kongLatency: res.headers.get('x-kong-proxy-latency') }
  if (res.headers.get('x-envelope') === '1') {
    const env = JSON.parse(raw)
    const aad = enc.encode(`envelope-v1|res|${method}|${path}|${s.sid}|${seq}`)
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv), additionalData: aad }, s.key, unb64(env.ct))
    out.data = JSON.parse(dec.decode(plain))
  } else {
    try { out.data = JSON.parse(raw) } catch { out.data = raw }
  }
  out.seq = seq
  return out
}

let passed = 0, failed = 0
async function check(name, fn) {
  try { await fn(); passed++; console.log(`PASS  ${name}`) }
  catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.message}`) }
}
const expect = (cond, msg) => { if (!cond) throw new Error(msg) }

const s = await handshake(KEY)
console.log(`Session opened for ${KEY}: ${s.sid.slice(0, 8)}…, expires in ${s.expiresIn}s\n`)

await check('GET /secure/api-a/accounts: response encrypted on the wire, decrypts correctly', async () => {
  const r = await call(s, 'GET', '/secure/api-a/accounts')
  expect(r.status === 200, `status ${r.status}: ${r.raw}`)
  expect(!r.raw.includes('CUST-001'), 'plaintext visible on the wire')
  expect(Array.isArray(r.data.accounts), 'decrypted body has no accounts')
  console.log(`      wire: ${r.raw.slice(0, 70)}…`)
})

await check('GET /secure/api-b/transactions: two-hop call (B calls C) works behind the envelope', async () => {
  const r = await call(s, 'GET', '/secure/api-b/transactions?customerId=CUST-001')
  expect(r.status === 200, `status ${r.status}: ${r.raw}`)
  expect(r.data.customer && r.data.transactions.length > 0, 'unexpected decrypted body')
})

await check('Plain route /api-a/accounts still works without encryption (comparison baseline)', async () => {
  const r = await fetch(`${BASE}/api-a/accounts`)
  expect(r.status === 200 && !r.headers.get('x-envelope'), `status ${r.status}`)
})

await check('Replaying a sequence number -> 409 ENVELOPE_REPLAY', async () => {
  const first = await call(s, 'GET', '/secure/api-a/accounts')
  const again = await call(s, 'GET', '/secure/api-a/accounts', undefined, { seq: first.seq })
  expect(again.status === 409 && again.data.code === 'ENVELOPE_REPLAY', `got ${again.status} ${again.raw}`)
})

await check('Stale timestamp -> 409 ENVELOPE_STALE', async () => {
  const r = await call(s, 'GET', '/secure/api-a/accounts', undefined, { ts: Date.now() - 5 * 60_000 })
  expect(r.status === 409 && r.data.code === 'ENVELOPE_STALE', `got ${r.status} ${r.raw}`)
})

await check("Using this session with another team's key -> 403 ENVELOPE_OWNER", async () => {
  const r = await call(s, 'GET', '/secure/api-a/accounts', undefined, { apikey: OTHER_KEY })
  expect(r.status === 403 && r.data.code === 'ENVELOPE_OWNER', `got ${r.status} ${r.raw}`)
})

await check('Unknown session -> 401 ENVELOPE_SESSION', async () => {
  const r = await call(s, 'GET', '/secure/api-a/accounts', undefined, { sid: 'no-such-session' })
  expect(r.status === 401 && r.data.code === 'ENVELOPE_SESSION', `got ${r.status} ${r.raw}`)
})

await check('No API key -> 401 from key-auth (before the envelope plugin runs)', async () => {
  const r = await fetch(`${BASE}/secure/api-a/accounts`)
  expect(r.status === 401, `got ${r.status}`)
})

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
