-- Envelope v1 plugin for Kong 3.9 (see "Envelope Encryption for Kong: Specification v1").
--   mode = "handshake": answers POST /envelope/handshake itself (spec section 3)
--   mode = "protect"  : decrypts requests and encrypts upstream responses (sections 4 to 7)
local crypto = require "kong.plugins.envelope.crypto"
local b64url = require "ngx.base64"
local json   = require("cjson.safe").new()
if json.encode_escape_forward_slash then   -- OpenResty cjson (in Kong) supports this
  json.encode_escape_forward_slash(false)
end

local ngx = ngx
local kong = kong
local tonumber, type, tostring, abs = tonumber, type, tostring, math.abs
local fmt, find, sub, lower = string.format, string.find, string.sub, string.lower

local Envelope = {
  PRIORITY = 1000,   -- after cors (2000) and key-auth (1250), before rate-limiting (910)
  VERSION = "0.1.0",
}

local DICT = "envelope_sessions"
local AAD_PREFIX = "envelope-v1"
local HANDSHAKE_MAX_BODY = 8192
local H_SESSION, H_SEQ, H_TS = "X-Envelope-Session", "X-Envelope-Seq", "X-Envelope-Ts"

-- Plain error responses (spec section 8). Generic messages; details go to the log.
local function reject(status, code, message, log_detail)
  if log_detail then
    kong.log.info(code, ": ", log_detail)
  end
  return kong.response.exit(status, { code = code, message = message })
end

local function shm()
  local dict = ngx.shared[DICT]
  if not dict then
    kong.log.err("lua_shared_dict '", DICT, "' is not configured; set KONG_NGINX_HTTP_LUA_SHARED_DICT")
  end
  return dict
end

local function single_header(name)
  local v = kong.request.get_header(name)
  if type(v) == "table" then
    return nil   -- repeated header: treat as malformed
  end
  return v
end

-- Session record stored as "key_b64|consumer_id|expiry_epoch"
local function load_session(dict, sid)
  local rec = dict:get("s:" .. sid)
  if not rec then
    return nil
  end
  local p1 = find(rec, "|", 1, true)
  local p2 = p1 and find(rec, "|", p1 + 1, true)
  if not p2 then
    return nil
  end
  local key = ngx.decode_base64(sub(rec, 1, p1 - 1))
  local expiry = tonumber(sub(rec, p2 + 1))
  if not key or not expiry or expiry <= ngx.now() then
    return nil
  end
  return { key = key, consumer = sub(rec, p1 + 1, p2 - 1), expiry = expiry }
end

---------------------------------------------------------------------------
-- Handshake (spec section 3)
---------------------------------------------------------------------------
local function handshake(conf)
  local dict = shm()
  if not dict then
    return reject(500, "ENVELOPE_CONFIG", "Envelope is not configured on this gateway")
  end
  if kong.request.get_method() ~= "POST" then
    return reject(405, "ENVELOPE_BAD_HANDSHAKE", "Handshake requires POST")
  end

  local consumer = kong.client.get_consumer()
  if conf.require_consumer and not consumer then
    return reject(401, "ENVELOPE_NO_CONSUMER", "No consumer identified")
  end

  local raw = kong.request.get_raw_body(HANDSHAKE_MAX_BODY)
  local body = raw and json.decode(raw)
  local pub = type(body) == "table" and body.pub
  if type(body) ~= "table" or body.v ~= 1 or type(pub) ~= "table"
     or pub.kty ~= "EC" or pub.crv ~= "P-256"
     or type(pub.x) ~= "string" or type(pub.y) ~= "string" then
    return reject(400, "ENVELOPE_BAD_HANDSHAKE", "Invalid handshake request")
  end

  -- Rebuild the JWK from the four allowed fields only (never pass "d" or other fields through)
  local client_jwk = json.encode({ kty = "EC", crv = "P-256", x = pub.x, y = pub.y })
  local key, server_jwk_json, salt = crypto.handshake(client_jwk)
  if not key then
    return reject(400, "ENVELOPE_BAD_HANDSHAKE", "Invalid handshake request", server_jwk_json)
  end
  local server_jwk = json.decode(server_jwk_json)

  local sid = b64url.encode_base64url(crypto.random(32))
  local expiry = ngx.now() + conf.session_ttl
  local consumer_id = consumer and consumer.id or ""
  local ok, err, forcible = dict:set("s:" .. sid,
                                     ngx.encode_base64(key) .. "|" .. consumer_id .. "|" .. fmt("%.3f", expiry),
                                     conf.session_ttl)
  if not ok then
    kong.log.err("storing session failed: ", err)
    return reject(503, "ENVELOPE_CONFIG", "Session store unavailable")
  end
  if forcible then
    kong.log.warn("session store full: older entries were evicted; consider a larger ", DICT)
  end

  kong.log.info("envelope session opened for consumer ", consumer_id, " sid ", sub(sid, 1, 8), "…")
  local response = json.encode({
    v = 1,
    sid = sid,
    pub = { kty = server_jwk.kty, crv = server_jwk.crv, x = server_jwk.x, y = server_jwk.y },
    salt = ngx.encode_base64(salt),
    expires_in = conf.session_ttl,
    kid = json.null,
  })
  return kong.response.exit(200, response, {
    ["Content-Type"] = "application/json",
    ["Cache-Control"] = "no-store",
  })
end

---------------------------------------------------------------------------
-- Protect: request side (spec sections 4, 6, 7)
---------------------------------------------------------------------------
local function is_enveloped(conf, method)
  for _, m in ipairs(conf.enveloped_methods) do
    if m == method then
      return true
    end
  end
  return false
end

local function protect_request(conf)
  local method = kong.request.get_method()
  if method == "OPTIONS" then
    return   -- CORS preflight is answered by the cors plugin; never enveloped
  end

  local dict = shm()
  if not dict then
    return reject(500, "ENVELOPE_CONFIG", "Envelope is not configured on this gateway")
  end

  -- 1. Consumer identified?
  local consumer = kong.client.get_consumer()
  if conf.require_consumer and not consumer then
    return reject(401, "ENVELOPE_NO_CONSUMER", "No consumer identified")
  end

  -- 2. Session valid?
  local sid = single_header(H_SESSION)
  if not sid or #sid > 64 then
    return reject(401, "ENVELOPE_SESSION", "Session missing or expired; handshake again")
  end
  local session = load_session(dict, sid)
  if not session then
    return reject(401, "ENVELOPE_SESSION", "Session missing or expired; handshake again",
                  "unknown or expired sid " .. sub(sid, 1, 8))
  end

  -- 3. Session owned by this consumer?
  local consumer_id = consumer and consumer.id or ""
  if session.consumer ~= consumer_id then
    return reject(403, "ENVELOPE_OWNER", "Session belongs to a different consumer",
                  "sid " .. sub(sid, 1, 8) .. " owner " .. session.consumer .. " used by " .. consumer_id)
  end

  local seq = single_header(H_SEQ)
  local ts = single_header(H_TS)
  if not seq or not find(seq, "^[1-9]%d*$") or #seq > 15
     or not ts or not find(ts, "^%d+$") or #ts > 16 then
    return reject(400, "ENVELOPE_MISSING", "Envelope headers missing or malformed")
  end

  local path = kong.request.get_raw_path()
  local plaintext

  -- 4. Decrypt (enveloped methods only)
  if is_enveloped(conf, method) then
    local ctype = kong.request.get_header("Content-Type")
    if type(ctype) ~= "string" or not find(lower(ctype), "^application/json") then
      return reject(415, "ENVELOPE_UNSUPPORTED", "Enveloped requests must be application/json")
    end

    -- An envelope is base64 of (plaintext + 16-byte tag) plus a small JSON wrapper
    local max_envelope = math.ceil((conf.max_body_size + 16) / 3) * 4 + 512
    local declared = tonumber(kong.request.get_header("Content-Length") or nil)
    if declared and declared > max_envelope then
      return reject(413, "ENVELOPE_TOO_LARGE", "Request body exceeds the limit for this route")
    end

    local raw, read_err = kong.request.get_raw_body(max_envelope)
    if not raw then
      if read_err and find(read_err, "too big", 1, true) then
        return reject(413, "ENVELOPE_TOO_LARGE", "Request body exceeds the limit for this route")
      end
      return reject(400, "ENVELOPE_MISSING", "Envelope missing or malformed", read_err)
    end
    if #raw > max_envelope then
      return reject(413, "ENVELOPE_TOO_LARGE", "Request body exceeds the limit for this route")
    end

    local env = json.decode(raw)
    if type(env) ~= "table" or type(env.iv) ~= "string" or type(env.ct) ~= "string" then
      return reject(400, "ENVELOPE_MISSING", "Envelope missing or malformed")
    end
    if env.v ~= 1 then
      return reject(400, "ENVELOPE_BAD", "Envelope could not be decrypted", "unknown version")
    end
    local iv, ct = ngx.decode_base64(env.iv), ngx.decode_base64(env.ct)
    if not iv or not ct then
      return reject(400, "ENVELOPE_MISSING", "Envelope missing or malformed")
    end

    local aad = AAD_PREFIX .. "|req|" .. method .. "|" .. path .. "|" .. sid .. "|" .. seq .. "|" .. ts
    local err
    plaintext, err = crypto.decrypt(session.key, iv, ct, aad)
    if not plaintext then
      return reject(400, "ENVELOPE_BAD", "Envelope could not be decrypted",
                    "consumer " .. consumer_id .. " sid " .. sub(sid, 1, 8) .. ": " .. tostring(err))
    end
    if #plaintext > conf.max_body_size then
      return reject(413, "ENVELOPE_TOO_LARGE", "Request body exceeds the limit for this route")
    end
  end

  -- 5. Not a replay? (authenticated for enveloped methods via the AAD)
  local now = ngx.now()
  if abs(tonumber(ts) - now * 1000) > conf.clock_skew * 1000 then
    return reject(409, "ENVELOPE_STALE", "Request timestamp outside the allowed window")
  end
  if tonumber(seq) > conf.max_seq_per_session then
    return reject(401, "ENVELOPE_SESSION", "Session request budget used; handshake again")
  end
  local remaining = math.max(1, math.ceil(session.expiry - now))
  local added, add_err = dict:add("q:" .. sid .. ":" .. seq, true, remaining)
  if not added then
    if add_err == "exists" then
      return reject(409, "ENVELOPE_REPLAY", "Sequence number already used",
                    "consumer " .. consumer_id .. " sid " .. sub(sid, 1, 8) .. " seq " .. seq)
    end
    kong.log.err("recording sequence failed: ", add_err)
    return reject(503, "ENVELOPE_CONFIG", "Session store unavailable")
  end

  -- Forward plain JSON, byte for byte
  if plaintext then
    kong.service.request.set_raw_body(plaintext)
    kong.service.request.set_header("Content-Type", "application/json")
  end
  kong.service.request.clear_header(H_SESSION)
  kong.service.request.clear_header(H_SEQ)
  kong.service.request.clear_header(H_TS)
  kong.service.request.clear_header("Accept-Encoding")   -- we must encrypt an uncompressed body

  local ctx = kong.ctx.plugin
  ctx.key = session.key
  ctx.res_aad = AAD_PREFIX .. "|res|" .. method .. "|" .. path .. "|" .. sid .. "|" .. seq
  ctx.max = conf.max_body_size
  ctx.method = method
end

function Envelope:access(conf)
  if conf.mode == "handshake" then
    return handshake(conf)
  end
  return protect_request(conf)
end

---------------------------------------------------------------------------
-- Protect: response side (spec sections 5 and 7)
---------------------------------------------------------------------------
local TOO_LARGE_BODY = '{"code":"ENVELOPE_RESPONSE_TOO_LARGE","message":"Response exceeds the limit for this route"}'

function Envelope:header_filter(conf)
  local ctx = kong.ctx.plugin
  if not ctx.key then
    return
  end
  -- Only bodies that came from the upstream API; Kong's own responses stay plain
  if kong.response.get_source() ~= "service" then
    ctx.key = nil
    return
  end
  local status = kong.response.get_status()
  local declared = tonumber(kong.response.get_header("Content-Length") or nil)
  if ctx.method == "HEAD" or status == 204 or status == 304 or declared == 0 then
    ctx.key = nil
    return
  end

  local upstream_type = kong.response.get_header("Content-Type")   -- read before overwriting
  kong.response.clear_header("Content-Length")   -- the body size changes; sent chunked
  kong.response.set_header("Content-Type", "application/json")

  if declared and declared > ctx.max then
    -- Fail closed before any byte is sent
    ctx.too_large = true
    kong.response.set_status(502)
    kong.log.warn("upstream response of ", declared, " bytes exceeds limit ", ctx.max)
    return
  end

  kong.response.set_header("X-Envelope-Content-Type", upstream_type or "")
  kong.response.set_header("X-Envelope", "1")
  ctx.encrypt = true
end

function Envelope:body_filter(conf)
  local ctx = kong.ctx.plugin
  if not (ctx.encrypt or ctx.too_large) then
    return
  end

  local chunk, eof = ngx.arg[1], ngx.arg[2]

  if not ctx.too_large then
    ctx.size = (ctx.size or 0) + #(chunk or "")
    if ctx.size > ctx.max then
      -- Response grew past the limit while streaming: stop buffering and never send it plain.
      -- Headers are already out (status 200, X-Envelope: 1); the body below is not a valid
      -- envelope, so a client following the spec treats it as an error.
      ctx.too_large = true
      ctx.encrypt = nil
      ngx.ctx.KONG_BODY_BUFFER = nil
      kong.log.warn("upstream response exceeded limit ", ctx.max, " while streaming")
    end
  end

  if ctx.too_large then
    ngx.ctx.KONG_BODY_BUFFER = nil
    ngx.arg[1] = eof and TOO_LARGE_BODY or nil
    return
  end

  local body = kong.response.get_raw_body()   -- nil until the last chunk has arrived
  if not body then
    return
  end

  local iv, ct = crypto.encrypt(ctx.key, body, ctx.res_aad)
  if not iv then
    kong.log.err("response encryption failed: ", ct)
    return kong.response.set_raw_body('{"code":"ENVELOPE_CONFIG","message":"Response could not be encrypted"}')
  end
  kong.response.set_raw_body(json.encode({
    v = 1,
    iv = ngx.encode_base64(iv),
    ct = ngx.encode_base64(ct),
  }))
end

return Envelope
