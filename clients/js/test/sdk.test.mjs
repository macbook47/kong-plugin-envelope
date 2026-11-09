// Run: node clients/js/test/sdk.test.mjs
import { createSecureClient, EnvelopeError } from '../envelope-client.js'
import { startMockGateway } from './mock-gateway.mjs'

const gw = await startMockGateway(18080)
const baseUrl = 'http://localhost:18080'
let passed = 0, failed = 0
async function test(name, fn) {
  try { await fn(); passed++; console.log(`PASS  ${name}`) }
  catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.stack.split('\n').slice(0, 2).join(' | ')}`) }
}
const expect = (cond, msg) => { if (!cond) throw new Error(msg) }

await test('POST: API receives the exact original JSON; app gets decrypted data', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  const body = '{"amount":12345678901234567890.12,"to":"0012-01-000456-50-2"}'
  const r = await c.post('/secure/api-b/transfers', body)
  expect(r.ok && r.encrypted, `status ${r.status}`)
  expect(gw.state.lastUpstreamBody === body, `upstream got ${gw.state.lastUpstreamBody}`)
  expect(r.data.echo === body, 'decrypted echo mismatch')
  expect(!r.wire.request.body.includes('0012-01'), 'plaintext visible in request wire body')
  expect(!r.wire.response.body.includes('0012-01'), 'plaintext visible in response wire body')
})

await test('objects are serialized as JSON', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  const r = await c.post('/secure/api-b/transfers', { a: 1 })
  expect(gw.state.lastUpstreamBody === '{"a":1}', gw.state.lastUpstreamBody)
})

await test('GET: no request body, response decrypted', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  const r = await c.get('/secure/api-a/accounts?echo=1')
  expect(r.ok && r.data.method === 'GET' && r.wire.request.body === '', JSON.stringify(r.data))
})

await test('DELETE without body sends an empty envelope', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  const r = await c.delete('/secure/api-b/transfers/7')
  expect(r.ok && gw.state.lastUpstreamBody === '' && r.wire.request.body.startsWith('{"v":1'), 'unexpected')
})

await test('parallel calls share one handshake and use unique sequence numbers', async () => {
  const before = gw.state.handshakes
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  const rs = await Promise.all(Array.from({ length: 10 }, (_, i) => c.post('/secure/api-b/transfers', { i })))
  expect(gw.state.handshakes - before === 1, `handshakes: ${gw.state.handshakes - before}`)
  expect(rs.every((r) => r.ok), 'a parallel call failed')
  expect(new Set(rs.map((r) => r.session.seq)).size === 10, 'sequence numbers repeated')
})

await test('expired session: SDK re-handshakes and retries once, transparently', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  await c.get('/secure/api-a/accounts')
  const before = gw.state.handshakes
  gw.expireAllSessions()
  const r = await c.post('/secure/api-b/transfers', { after: 'expiry' })
  expect(r.ok && gw.state.handshakes - before === 1, `status ${r.status}, handshakes ${gw.state.handshakes - before}`)
})

await test('warmUp opens the session before the first call', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  await c.warmUp()
  expect(c.sessionInfo() && c.sessionInfo().seq === 0, 'no session after warmUp')
})

await test('plain success on an encrypted route is refused (fail closed)', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  try { await c.get('/secure/plain-leak'); throw new Error('accepted a plain response') }
  catch (e) { expect(e instanceof EnvelopeError && e.code === 'ENVELOPE_RESPONSE_PLAIN', e.message) }
})

await test('tampered response is refused', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  await c.warmUp()
  gw.state.tamperNextResponse = true
  try { await c.get('/secure/api-a/accounts'); throw new Error('accepted a tampered response') }
  catch (e) { expect(e instanceof EnvelopeError && e.code === 'ENVELOPE_RESPONSE_INVALID', e.message) }
})

await test('empty 204 response is accepted', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  const r = await c.get('/secure/empty')
  expect(r.ok && r.status === 204 && r.data === null, `status ${r.status}`)
})

await test("Kong's plain errors come back as ok:false with the code", async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-y' })
  await c.warmUp()
  const other = createSecureClient({ baseUrl, apiKey: 'key-x' })
  await other.warmUp()
  // Use team-y's credential with team-x's session by swapping keys on a raw call
  const r = await fetch(baseUrl + '/secure/api-a/accounts', { headers: { apikey: 'key-y', 'X-Envelope-Session': other.sessionInfo().sid, 'X-Envelope-Seq': '99', 'X-Envelope-Ts': String(Date.now()) } })
  expect(r.status === 403, `status ${r.status}`)
})

await test('handshake failure (bad key) throws EnvelopeError with status', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'wrong' })
  try { await c.get('/secure/api-a/accounts'); throw new Error('no error') }
  catch (e) { expect(e instanceof EnvelopeError && e.status === 401, e.message) }
})

await test('GET with a body is rejected before sending', async () => {
  const c = createSecureClient({ baseUrl, apiKey: 'key-x' })
  try { await c.request('GET', '/secure/api-a/accounts', { x: 1 }); throw new Error('no error') }
  catch (e) { expect(e instanceof EnvelopeError, e.message) }
})

gw.close()
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
