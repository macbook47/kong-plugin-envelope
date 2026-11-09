// Envelope v1 client (see docs/SPEC.md). No dependencies: uses Web Crypto and fetch,
// available in all modern browsers and in Node 18+.
//
//   const client = createSecureClient({ baseUrl: 'http://localhost:8000', apiKey: 'poc-ui-key' })
//   const res = await client.post('/secure/api-b/transfers', { to: '...', amount: 1500000 })
//   res.ok, res.status, res.data          -> what the app normally needs
//   res.wire.request / res.wire.response  -> exactly what travelled (for inspection and debugging)

const enc = new TextEncoder()
const dec = new TextDecoder()
const ENVELOPED = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

function b64(bytes) {
  const a = new Uint8Array(bytes)
  let s = ''
  for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000))
  return btoa(s)
}
const unb64 = (str) => Uint8Array.from(atob(str), (ch) => ch.charCodeAt(0))

export class EnvelopeError extends Error {
  constructor(message, { status, code } = {}) {
    super(message)
    this.name = 'EnvelopeError'
    this.status = status
    this.code = code
  }
}

function errorCode(raw) {
  try { return JSON.parse(raw).code } catch { return undefined }
}

function parseBody(text, contentType) {
  if (!text) return null
  if (!contentType || contentType.includes('json')) {
    try { return JSON.parse(text) } catch { /* fall through */ }
  }
  return text
}

export function createSecureClient(options) {
  const {
    baseUrl,
    apiKey,
    credentialHeader = 'apikey',
    handshakePath = '/envelope/handshake',
    renewBeforeMs = 30_000,                      // re-handshake shortly before the session expires
    fetchImpl = globalThis.fetch.bind(globalThis),
    crypto: cryptoImpl = globalThis.crypto,
  } = options
  if (!baseUrl) throw new Error('baseUrl is required')
  const subtle = cryptoImpl.subtle

  let session = null
  let pending = null

  // Spec section 3. The ECDH private key and the session key are non-extractable.
  async function handshake() {
    const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
    const jwk = await subtle.exportKey('jwk', kp.publicKey)
    const res = await fetchImpl(baseUrl + handshakePath, {
      method: 'POST',
      headers: { [credentialHeader]: apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ v: 1, pub: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }),
    })
    const raw = await res.text()
    if (res.status !== 200) {
      throw new EnvelopeError(`Handshake failed with status ${res.status}`, { status: res.status, code: errorCode(raw) })
    }
    const body = JSON.parse(raw)
    if (body.v !== 1 || !body.sid || !body.pub || !body.salt) {
      throw new EnvelopeError('Handshake response is not envelope v1', { status: res.status })
    }
    const serverPub = await subtle.importKey('jwk', body.pub, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
    const secret = await subtle.deriveBits({ name: 'ECDH', public: serverPub }, kp.privateKey, 256)
    const hkdf = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey'])
    const key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: unb64(body.salt), info: enc.encode('envelope-v1') },
      hkdf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    return { sid: body.sid, key, seq: 0, expiresAt: Date.now() + body.expires_in * 1000 }
  }

  // One handshake at a time, shared by concurrent calls. `failed` = the session a call just saw rejected.
  async function ensureSession(failed) {
    const fresh = session && session !== failed && Date.now() < session.expiresAt - renewBeforeMs
    if (fresh) return session
    if (!pending) {
      pending = handshake().then((s) => { session = s; return s }).finally(() => { pending = null })
    }
    return pending
  }

  // Spec section 4: one attempt on the wire.
  async function send(s, method, pathWithQuery, body) {
    const path = pathWithQuery.split('?')[0]
    const seq = ++s.seq
    const ts = String(Date.now())
    const headers = {
      [credentialHeader]: apiKey,
      'X-Envelope-Session': s.sid,
      'X-Envelope-Seq': String(seq),
      'X-Envelope-Ts': ts,
    }
    let plainText = ''
    let wireBody
    if (ENVELOPED.has(method)) {
      plainText = body === undefined ? '' : (typeof body === 'string' ? body : JSON.stringify(body))
      const iv = cryptoImpl.getRandomValues(new Uint8Array(12))
      const aad = enc.encode(`envelope-v1|req|${method}|${path}|${s.sid}|${seq}|${ts}`)
      const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, s.key, enc.encode(plainText))
      wireBody = JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) })
      headers['Content-Type'] = 'application/json'
    } else if (body !== undefined) {
      throw new EnvelopeError(`${method} requests cannot carry a body`)
    }
    const started = (globalThis.performance || Date).now()
    const res = await fetchImpl(baseUrl + pathWithQuery, { method, headers, body: wireBody })
    const raw = await res.text()
    const elapsedMs = Math.round((globalThis.performance || Date).now() - started)
    return { res, raw, seq, path, headers, wireBody, plainText, elapsedMs }
  }

  // Spec section 5: open the response, refusing anything that should have been encrypted but wasn't.
  async function open(s, method, r) {
    const { res, raw } = r
    let text
    let contentType
    if (res.headers.get('x-envelope') === '1') {
      let env
      try { env = JSON.parse(raw) } catch { /* handled below */ }
      if (!env || env.v !== 1 || typeof env.iv !== 'string' || typeof env.ct !== 'string') {
        throw new EnvelopeError('Response marked as encrypted is not a valid envelope', { status: res.status, code: 'ENVELOPE_RESPONSE_INVALID' })
      }
      const aad = enc.encode(`envelope-v1|res|${method}|${r.path}|${s.sid}|${r.seq}`)
      let plain
      try {
        plain = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv), additionalData: aad }, s.key, unb64(env.ct))
      } catch {
        throw new EnvelopeError('Response could not be decrypted', { status: res.status, code: 'ENVELOPE_RESPONSE_INVALID' })
      }
      text = dec.decode(plain)
      contentType = res.headers.get('x-envelope-content-type')
    } else {
      if (res.ok && raw.length > 0) {
        throw new EnvelopeError('Plain response on an encrypted route was refused', { status: res.status, code: 'ENVELOPE_RESPONSE_PLAIN' })
      }
      text = raw   // empty success (e.g. 204) or a plain error generated by Kong
      contentType = res.headers.get('content-type')
    }
    const data = parseBody(text, contentType)
    return {
      ok: res.ok,
      status: res.status,
      data,
      error: res.ok ? null : { code: data && data.code, message: (data && data.message) || res.statusText },
      headers: res.headers,
      encrypted: res.headers.get('x-envelope') === '1',
      timings: { totalMs: r.elapsedMs, kongMs: Number(res.headers.get('x-kong-proxy-latency')) || null,
                 upstreamMs: Number(res.headers.get('x-kong-upstream-latency')) || null },
      wire: {
        request: { method, url: baseUrl + (r.path), headers: r.headers, body: r.wireBody || '' },
        response: { body: raw },
      },
      plain: { request: r.plainText, response: text },
      session: { sid: s.sid, seq: r.seq },
    }
  }

  async function request(method, pathWithQuery, body) {
    method = method.toUpperCase()
    let s = await ensureSession()
    let r = await send(s, method, pathWithQuery, body)
    // Spec section 6: the only automatic retry. It is safe: the request never reached the API.
    if (r.res.status === 401 && errorCode(r.raw) === 'ENVELOPE_SESSION') {
      s = await ensureSession(s)
      r = await send(s, method, pathWithQuery, body)
    }
    return open(s, method, r)
  }

  return {
    request,
    get: (path) => request('GET', path),
    post: (path, body) => request('POST', path, body),
    put: (path, body) => request('PUT', path, body),
    patch: (path, body) => request('PATCH', path, body),
    delete: (path, body) => request('DELETE', path, body),
    /** Opens the session now (for example at app start) so the first real call is not delayed. */
    warmUp: () => ensureSession().then(() => undefined),
    sessionInfo: () => (session ? { sid: session.sid, seq: session.seq, expiresAt: session.expiresAt } : null),
    /** Drops the session, for example at logout. */
    reset: () => { session = null },
  }
}
