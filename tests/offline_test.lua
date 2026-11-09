-- Offline tests for the envelope plugin, using a simulated Kong 3.9 PDK.
-- Needs LuaJIT, OpenSSL 3 and lua-resty-openssl 1.5.1 (the version bundled with Kong 3.9).
-- Run from the repository root:  ./tests/run.sh
local ROOT = (arg and arg[0] or ""):match("^(.*)/tests/[^/]+$") or "."
local LRO = os.getenv("LUA_RESTY_OPENSSL") or (ROOT .. "/.deps/lua-resty-openssl/lib")
package.path = table.concat({
  ROOT .. "/?.lua",                     -- kong/plugins/envelope/*.lua
  ROOT .. "/tests/?.lua",
  LRO .. "/?.lua", LRO .. "/?/init.lua",
  package.path }, ";")
local ffi = require "ffi"
ffi.load(os.getenv("OPENSSL_CRYPTO_LIB") or "crypto", true)
ffi.load(os.getenv("OPENSSL_SSL_LIB") or "ssl", true)
local b64 = require "b64"
local ok_cjson, cjson = pcall(require, "cjson")
if not ok_cjson then error("lua-cjson is required (luarocks install lua-cjson)") end

---------------------------------------------------------------- simulated ngx
local clock = 1794200000.0
local function new_dict()
  local data = {}
  local d = {}
  local function live(k) local e = data[k]; if e and (not e.exp or e.exp > clock) then return e end; data[k] = nil end
  function d:get(k) local e = live(k); return e and e.v end
  function d:set(k, v, ttl) data[k] = { v = v, exp = ttl and ttl > 0 and clock + ttl or nil }; return true, nil, false end
  function d:add(k, v, ttl) if live(k) then return false, "exists" end; return self:set(k, v, ttl) end
  return d
end
local DICT = new_dict()
_G.ngx = {
  now = function() return clock end,
  shared = { envelope_sessions = DICT },
  encode_base64 = b64.encode,
  decode_base64 = b64.decode,
  arg = {}, ctx = {}, null = cjson.null,
  log = function() end, WARN = 5, DEBUG = 8, ERR = 4, INFO = 7,
}
package.preload["ngx.base64"] = function()
  return { encode_base64url = b64.encode_url, decode_base64url = b64.decode_url }
end

---------------------------------------------------------------- simulated kong PDK
local R  -- current request/response state
local function hget(t, name) for k, v in pairs(t) do if k:lower() == name:lower() then return v end end end
local function hdel(t, name) for k in pairs(t) do if k:lower() == name:lower() then t[k] = nil end end end
local EXIT = {}
_G.kong = {
  log = { info = function() end, warn = function() end, err = function(...) io.stderr:write("ERR ", table.concat({...}), "\n") end },
  ctx = {},
  client = { get_consumer = function() return R.consumer end },
  request = {
    get_method = function() return R.method end,
    get_raw_path = function() return R.path end,
    get_header = function(n) return hget(R.headers, n) end,
    get_raw_body = function(max)
      if max and #R.body > max then return nil, "request body file too big: " .. #R.body .. " > " .. max end
      return R.body
    end,
  },
  service = { request = {
    set_raw_body = function(b) R.up_body = b end,
    set_header = function(n, v) hdel(R.headers, n); R.headers[n] = v end,
    clear_header = function(n) hdel(R.headers, n) end,
  } },
  response = {
    exit = function(status, body, headers)
      R.exit = { status = status, body = type(body) == "table" and cjson.encode(body) or body, headers = headers or {} }
      error(EXIT)
    end,
    get_source = function() return R.source end,
    get_status = function() return R.status end,
    get_header = function(n) return hget(R.resp_headers, n) end,
    set_header = function(n, v) hdel(R.resp_headers, n); R.resp_headers[n] = v end,
    clear_header = function(n) hdel(R.resp_headers, n) end,
    set_status = function(s) R.status = s end,
    -- Same logic as kong/pdk/response.lua in Kong 3.9.0
    get_raw_body = function()
      local buf, chunk, eof = ngx.ctx.KONG_BODY_BUFFER, ngx.arg[1], ngx.arg[2]
      if eof and not buf then return chunk end
      if type(chunk) == "string" and chunk ~= "" then
        buf = buf or {}; ngx.ctx.KONG_BODY_BUFFER = buf; buf[#buf + 1] = chunk
      end
      if eof then
        local s = buf and table.concat(buf) or ""
        ngx.arg[1] = s; ngx.ctx.KONG_BODY_BUFFER = nil; return s
      end
      ngx.arg[1] = nil; return nil
    end,
    set_raw_body = function(b) ngx.arg[1] = (b == "" and "\n" or b); ngx.arg[2] = true; ngx.ctx.KONG_BODY_BUFFER = nil end,
  },
}

local handler = require "kong.plugins.envelope.handler"

local function conf(over)
  local c = { mode = "protect", session_ttl = 900, clock_skew = 60, max_seq_per_session = 100000,
              max_body_size = 1048576, require_consumer = true,
              enveloped_methods = { "POST", "PUT", "PATCH", "DELETE" } }
  for k, v in pairs(over or {}) do c[k] = v end
  return c
end

-- Runs one request through access -> (upstream) -> header_filter -> body_filter
-- upstream(req) returns status, headers, { chunk1, chunk2, ... }
local function proxy(c, req, upstream)
  local headers = {}
  for k, v in pairs(req.headers or {}) do headers[k] = v end   -- each send carries its own copy
  R = { method = req.method, path = req.path, headers = headers, body = req.body or "",
        consumer = req.consumer, resp_headers = {} }
  kong.ctx.plugin = {}; ngx.ctx = {}
  local ok, e = pcall(handler.access, handler, c)
  if not ok then
    if e ~= EXIT then error(e) end
    return { status = R.exit.status, body = R.exit.body, headers = R.exit.headers, exited = true }
  end
  R.source = "service"
  local status, headers, chunks = upstream({ body = R.up_body or R.body, headers = R.headers })
  R.status = status; R.resp_headers = headers
  handler:header_filter(c)
  local out = {}
  for i, chunk in ipairs(chunks) do
    ngx.arg = { chunk, i == #chunks }
    handler:body_filter(c)
    if ngx.arg[1] then out[#out + 1] = ngx.arg[1] end
  end
  return { status = R.status, body = table.concat(out), headers = R.resp_headers, upstream_req = R }
end

---------------------------------------------------------------- client side (follows the spec)
local pkey, kdf, cipher = require "resty.openssl.pkey", require "resty.openssl.kdf", require "resty.openssl.cipher"
local crypto = require "kong.plugins.envelope.crypto"

local function new_client(consumer)
  local cl = { consumer = consumer, seq = 0 }
  cl.priv = pkey.new({ type = "EC", curve = "prime256v1" })
  local jwk = cjson.decode(cl.priv:tostring("public", "JWK"))
  cl.pub = { kty = jwk.kty, crv = jwk.crv, x = jwk.x, y = jwk.y }
  return cl
end

local function do_handshake(cl, c)
  local res = proxy(conf({ mode = "handshake" }), { method = "POST", path = "/envelope/handshake",
    consumer = cl.consumer, body = cjson.encode({ v = 1, pub = cl.pub }) }, function() error("must not reach upstream") end)
  if res.status ~= 200 then return res end
  local b = cjson.decode(res.body)
  local server = pkey.new(cjson.encode(b.pub), { format = "JWK" })
  local secret = cl.priv:derive(server)
  cl.key = kdf.derive({ type = kdf.HKDF, md = "sha256", outlen = 32, salt = b64.decode(b.salt),
                        hkdf_key = secret, hkdf_info = "envelope-v1" })
  cl.sid, cl.seq = b.sid, 0
  return res, b
end

local function build(cl, method, path, plain, over)
  over = over or {}
  cl.seq = cl.seq + 1
  local seq = over.seq or cl.seq
  local ts = over.ts or string.format("%d", clock * 1000)
  local req = { method = method, path = path, consumer = over.consumer or cl.consumer,
                headers = { ["X-Envelope-Session"] = over.sid or cl.sid, ["X-Envelope-Seq"] = tostring(seq),
                            ["X-Envelope-Ts"] = ts, ["Content-Type"] = "application/json" } }
  if plain then
    local aad = "envelope-v1|req|" .. method .. "|" .. (over.aad_path or path) .. "|" .. (over.sid or cl.sid) .. "|" .. seq .. "|" .. ts
    local iv, ct = crypto.encrypt(over.key or cl.key, plain, aad)
    if over.tamper then ct = ct:sub(1, 3) .. string.char((ct:byte(4) + 1) % 256) .. ct:sub(5) end
    req.body = cjson.encode({ v = over.v or 1, iv = b64.encode(iv), ct = b64.encode(ct) })
  end
  return req, seq
end

local function open_response(cl, method, path, seq, res)
  local env = cjson.decode(res.body)
  local aad = "envelope-v1|res|" .. method .. "|" .. path .. "|" .. cl.sid .. "|" .. seq
  return crypto.decrypt(cl.key, b64.decode(env.iv), b64.decode(env.ct), aad)
end

---------------------------------------------------------------- tests
local passed, failed = 0, 0
local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then passed = passed + 1; print("PASS  " .. name)
  else failed = failed + 1; print("FAIL  " .. name .. "\n      " .. tostring(err)) end
end
local function eq(a, b, what) if a ~= b then error((what or "value") .. ": expected " .. tostring(b) .. ", got " .. tostring(a), 2) end end
local function code(res) return cjson.decode(res.body).code end

local TEAM_X = { id = "11111111-aaaa-4aaa-8aaa-111111111111", username = "team-x" }
local TEAM_Y = { id = "22222222-bbbb-4bbb-8bbb-222222222222", username = "team-y" }
local echo_json = function(body) return function() return 200, { ["Content-Type"] = "application/json" }, { body } end end

test("handshake: both sides derive a session", function()
  local cl = new_client(TEAM_X)
  local res, b = do_handshake(cl)
  eq(res.status, 200, "status"); eq(res.headers["Cache-Control"], "no-store", "cache header")
  eq(b.v, 1); eq(b.expires_in, 900); eq(b.kid, cjson.null, "kid")
  assert(#cl.key == 32, "32-byte key")
end)

test("handshake: no consumer -> 401 ENVELOPE_NO_CONSUMER", function()
  local res = do_handshake(new_client(nil))
  eq(res.status, 401); eq(code(res), "ENVELOPE_NO_CONSUMER")
end)

test("handshake: point not on curve -> 400 ENVELOPE_BAD_HANDSHAKE", function()
  local cl = new_client(TEAM_X)
  cl.pub.y = cl.pub.x   -- a point that is not on P-256
  local res = do_handshake(cl)
  eq(res.status, 400); eq(code(res), "ENVELOPE_BAD_HANDSHAKE")
end)

test("POST: API receives the exact original bytes (large numbers untouched)", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local original = '{"amount":12345678901234567890.12,"to":"0012-01-000456-50-2"}'
  local req, seq = build(cl, "POST", "/secure/api-b/transfers", original)
  local seen
  local res = proxy(conf(), req, function(up) seen = up; return 200, { ["Content-Type"] = "application/json" }, { '{"status":"accepted"}' } end)
  eq(seen.body, original, "upstream body")
  eq(hget(seen.headers, "X-Envelope-Session"), nil, "envelope headers removed")
  eq(hget(seen.headers, "Content-Type"), "application/json")
  eq(res.headers["X-Envelope"], "1"); eq(res.headers["X-Envelope-Content-Type"], "application/json")
  eq(open_response(cl, "POST", "/secure/api-b/transfers", seq, res), '{"status":"accepted"}', "decrypted response")
end)

test("response arriving in many chunks is encrypted as one body", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req, seq = build(cl, "GET", "/secure/api-a/accounts")
  local res = proxy(conf(), req, function() return 200, { ["Content-Type"] = "application/json" }, { '{"acc', 'ounts":[', '1,2,3]}' } end)
  eq(open_response(cl, "GET", "/secure/api-a/accounts", seq, res), '{"accounts":[1,2,3]}')
end)

test("replay of the same envelope -> 409 ENVELOPE_REPLAY", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{"a":1}')
  eq(proxy(conf(), req, echo_json("{}")).status, 200, "first")
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 409); eq(code(res), "ENVELOPE_REPLAY")
end)

test("requests out of order are fine (parallel calls)", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local r1 = build(cl, "POST", "/secure/api-b/transfers", '{"n":1}')
  local r2 = build(cl, "POST", "/secure/api-b/transfers", '{"n":2}')
  eq(proxy(conf(), r2, echo_json("{}")).status, 200, "seq 2 first")
  eq(proxy(conf(), r1, echo_json("{}")).status, 200, "then seq 1")
end)

test("timestamp outside the window -> 409 ENVELOPE_STALE", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}', { ts = string.format("%d", (clock - 120) * 1000) })
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 409); eq(code(res), "ENVELOPE_STALE")
end)

test("changing the timestamp header breaks decryption -> 400 ENVELOPE_BAD", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}')
  req.headers["X-Envelope-Ts"] = string.format("%d", clock * 1000 + 5)
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 400); eq(code(res), "ENVELOPE_BAD")
end)

test("session used with another team's credential -> 403 ENVELOPE_OWNER", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}', { consumer = TEAM_Y })
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 403); eq(code(res), "ENVELOPE_OWNER")
end)

test("unknown session -> 401 ENVELOPE_SESSION", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}', { sid = "not-a-real-session" })
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 401); eq(code(res), "ENVELOPE_SESSION")
end)

test("expired session -> 401 ENVELOPE_SESSION", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  clock = clock + 901
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}')
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 401); eq(code(res), "ENVELOPE_SESSION")
end)

test("tampered ciphertext -> 400 ENVELOPE_BAD", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local res = proxy(conf(), build(cl, "POST", "/secure/api-b/transfers", '{"a":1}', { tamper = true }), echo_json("{}"))
  eq(res.status, 400); eq(code(res), "ENVELOPE_BAD")
end)

test("envelope moved to another path -> 400 ENVELOPE_BAD", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}', { aad_path = "/secure/api-a/accounts" })
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 400); eq(code(res), "ENVELOPE_BAD")
end)

test("unknown envelope version -> 400 ENVELOPE_BAD", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local res = proxy(conf(), build(cl, "POST", "/secure/api-b/transfers", '{}', { v = 2 }), echo_json("{}"))
  eq(res.status, 400); eq(code(res), "ENVELOPE_BAD")
end)

test("missing sequence header -> 400 ENVELOPE_MISSING", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}')
  req.headers["X-Envelope-Seq"] = nil
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 400); eq(code(res), "ENVELOPE_MISSING")
end)

test("POST without JSON content type -> 415 ENVELOPE_UNSUPPORTED", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "POST", "/secure/api-b/transfers", '{}')
  req.headers["Content-Type"] = "multipart/form-data"
  local res = proxy(conf(), req, echo_json("{}"))
  eq(res.status, 415); eq(code(res), "ENVELOPE_UNSUPPORTED")
end)

test("request over the size limit -> 413 ENVELOPE_TOO_LARGE", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local big = '"' .. string.rep("x", 5000) .. '"'
  local res = proxy(conf({ max_body_size = 1024 }), build(cl, "POST", "/secure/api-b/transfers", big), echo_json("{}"))
  eq(res.status, 413); eq(code(res), "ENVELOPE_TOO_LARGE")
end)

test("sequence budget used -> 401 ENVELOPE_SESSION", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local res = proxy(conf({ max_seq_per_session = 3 }), build(cl, "POST", "/secure/api-b/transfers", '{}', { seq = 4 }), echo_json("{}"))
  eq(res.status, 401); eq(code(res), "ENVELOPE_SESSION")
end)

test("DELETE with empty envelope reaches the API with an empty body", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local seen
  local res = proxy(conf(), build(cl, "DELETE", "/secure/api-b/transfers/7", ""), function(up) seen = up; return 204, {}, { "" } end)
  eq(seen.body, "", "upstream body"); eq(res.status, 204); eq(res.headers["X-Envelope"], nil, "no envelope on 204")
end)

test("response with declared size over the limit -> 502, never sent plain", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local big = string.rep("y", 2000)
  local res = proxy(conf({ max_body_size = 1024 }), build(cl, "GET", "/secure/api-a/accounts"),
    function() return 200, { ["Content-Type"] = "application/json", ["Content-Length"] = tostring(#big) }, { big } end)
  eq(res.status, 502); eq(code(res), "ENVELOPE_RESPONSE_TOO_LARGE")
  assert(not res.body:find("yyyy"), "plaintext leaked")
end)

test("chunked response growing over the limit -> never sent plain", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local part = string.rep("z", 600)
  local res = proxy(conf({ max_body_size = 1024 }), build(cl, "GET", "/secure/api-a/accounts"),
    function() return 200, { ["Content-Type"] = "application/json" }, { part, part, part } end)
  eq(code(res), "ENVELOPE_RESPONSE_TOO_LARGE")
  assert(not res.body:find("zzzz"), "plaintext leaked")
end)

test("Kong's own responses (e.g. from another plugin) stay plain", function()
  local cl = new_client(TEAM_X); do_handshake(cl)
  local req = build(cl, "GET", "/secure/api-a/accounts")
  R = { method = req.method, path = req.path, headers = req.headers, body = "", consumer = req.consumer, resp_headers = {} }
  kong.ctx.plugin = {}; ngx.ctx = {}
  handler:access(conf())
  R.source = "exit"; R.status = 429; R.resp_headers = { ["Content-Type"] = "application/json" }
  handler:header_filter(conf())
  ngx.arg = { '{"message":"API rate limit exceeded"}', true }
  handler:body_filter(conf())
  eq(ngx.arg[1], '{"message":"API rate limit exceeded"}'); eq(R.resp_headers["X-Envelope"], nil)
end)

test("CORS preflight passes through untouched", function()
  local res = proxy(conf(), { method = "OPTIONS", path = "/secure/api-a/accounts", headers = {} }, echo_json(""))
  eq(res.exited, nil, "not rejected")
end)

print(string.format("\n%d passed, %d failed", passed, failed))
os.exit(failed == 0 and 0 or 1)
