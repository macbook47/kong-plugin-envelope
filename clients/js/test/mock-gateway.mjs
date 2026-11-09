// Test stand-in for Kong + the envelope plugin, implementing the Kong side of docs/SPEC.md.
// Only for exercising the SDK; the real plugin is tested in tests/offline_test.lua.
import http from 'node:http'
const { subtle } = globalThis.crypto
const enc = new TextEncoder(), dec = new TextDecoder()
const b64 = (b) => Buffer.from(b).toString('base64')
const KEYS = { 'key-x': 'team-x', 'key-y': 'team-y' }

export function startMockGateway(port) {
  const sessions = new Map(), seen = new Set()
  const state = { handshakes: 0, lastUpstreamBody: null, tamperNextResponse: false }
  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...headers })
    res.end(typeof body === 'string' ? body : JSON.stringify(body))
  }
  const server = http.createServer(async (req, res) => {
    const path = req.url.split('?')[0]
    let raw = ''; for await (const c of req) raw += c
    const consumer = KEYS[req.headers.apikey]
    if (!consumer) return send(res, 401, { message: 'No API key found in request' })

    if (path === '/envelope/handshake') {
      state.handshakes++
      const { pub } = JSON.parse(raw)
      const client = await subtle.importKey('jwk', pub, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
      const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
      const secret = await subtle.deriveBits({ name: 'ECDH', public: client }, kp.privateKey, 256)
      const salt = crypto.getRandomValues(new Uint8Array(32))
      const hk = await subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey'])
      const key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('envelope-v1') },
        hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
      const sid = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url')
      sessions.set(sid, { key, consumer })
      const j = await subtle.exportKey('jwk', kp.publicKey)
      return send(res, 200, { v: 1, sid, pub: { kty: j.kty, crv: j.crv, x: j.x, y: j.y }, salt: b64(salt), expires_in: 900, kid: null })
    }

    const sid = req.headers['x-envelope-session'], seq = req.headers['x-envelope-seq'], ts = req.headers['x-envelope-ts']
    const s = sessions.get(sid)
    if (!s) return send(res, 401, { code: 'ENVELOPE_SESSION', message: 'Session missing or expired; handshake again' })
    if (s.consumer !== consumer) return send(res, 403, { code: 'ENVELOPE_OWNER', message: 'Session belongs to a different consumer' })
    let upstreamBody = ''
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const env = JSON.parse(raw)
      try {
        const aad = enc.encode(`envelope-v1|req|${req.method}|${path}|${sid}|${seq}|${ts}`)
        upstreamBody = dec.decode(await subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(env.iv, 'base64'), additionalData: aad }, s.key, Buffer.from(env.ct, 'base64')))
      } catch { return send(res, 400, { code: 'ENVELOPE_BAD', message: 'Envelope could not be decrypted' }) }
    }
    if (seen.has(sid + ':' + seq)) return send(res, 409, { code: 'ENVELOPE_REPLAY', message: 'Sequence number already used' })
    seen.add(sid + ':' + seq)
    state.lastUpstreamBody = upstreamBody

    // "Upstream API"
    if (path === '/secure/plain-leak') return send(res, 200, { leaked: true })          // misconfigured route: no envelope
    if (path === '/secure/empty') { res.writeHead(204); return res.end() }
    const upstream = JSON.stringify({ echo: upstreamBody, method: req.method })

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const aad = enc.encode(`envelope-v1|res|${req.method}|${path}|${sid}|${seq}`)
    let ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, s.key, enc.encode(upstream)))
    if (state.tamperNextResponse) { ct[3] ^= 1; state.tamperNextResponse = false }
    send(res, 200, { v: 1, iv: b64(iv), ct: b64(ct) }, { 'X-Envelope': '1', 'X-Envelope-Content-Type': 'application/json', 'X-Kong-Proxy-Latency': '1' })
  })
  return new Promise((resolve) => server.listen(port, () => resolve({
    state, close: () => server.close(),
    expireAllSessions: () => sessions.clear(),
  })))
}
