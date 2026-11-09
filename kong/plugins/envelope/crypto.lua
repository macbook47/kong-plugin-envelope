-- Cryptographic core (spec section 2). Pure functions on raw bytes; no Kong PDK here,
-- so this file can be tested outside Kong. Verified against Web Crypto in Phase 1.
local pkey   = require "resty.openssl.pkey"
local kdf    = require "resty.openssl.kdf"
local cipher = require "resty.openssl.cipher"
local rand   = require "resty.openssl.rand"

local _M = {}

local HKDF_INFO = "envelope-v1"
local IV_LEN, TAG_LEN, KEY_LEN, SALT_LEN = 12, 16, 32, 32

function _M.random(n)
  return rand.bytes(n)
end

-- client_jwk_json: the client's public key as a JWK JSON string with kty, crv, x, y only.
-- Returns session_key, server_public_jwk_json, salt  or  nil, err
function _M.handshake(client_jwk_json)
  -- The library rejects points that are not on the curve (invalid-curve protection).
  local client, err = pkey.new(client_jwk_json, { format = "JWK" })
  if not client then
    return nil, "invalid client public key: " .. tostring(err)
  end

  local server = pkey.new({ type = "EC", curve = "prime256v1" })
  local secret
  secret, err = server:derive(client)
  if not secret then
    return nil, "ECDH failed: " .. tostring(err)
  end

  local salt = rand.bytes(SALT_LEN)
  local key
  key, err = kdf.derive({ type = kdf.HKDF, md = "sha256", outlen = KEY_LEN,
                          salt = salt, hkdf_key = secret, hkdf_info = HKDF_INFO })
  if not key then
    return nil, "HKDF failed: " .. tostring(err)
  end

  local server_jwk
  server_jwk, err = server:tostring("public", "JWK")
  if not server_jwk then
    return nil, "exporting server key failed: " .. tostring(err)
  end
  -- server private key and secret go out of scope here and are never stored
  return key, server_jwk, salt
end

-- Returns iv, ciphertext_with_tag  or  nil, err
function _M.encrypt(key, plaintext, aad)
  local iv = rand.bytes(IV_LEN)
  local c = cipher.new("aes-256-gcm")
  local ct, err = c:encrypt(key, iv, plaintext, false, aad)
  if not ct then
    return nil, err
  end
  local tag
  tag, err = c:get_aead_tag(TAG_LEN)
  if not tag then
    return nil, err
  end
  return iv, ct .. tag            -- Web Crypto layout: ciphertext followed by tag
end

-- Returns plaintext  or  nil, err   (fails on any tampering, wrong key or wrong AAD)
function _M.decrypt(key, iv, ct_with_tag, aad)
  if #iv ~= IV_LEN or #ct_with_tag < TAG_LEN then
    return nil, "malformed envelope sizes"
  end
  local c = cipher.new("aes-256-gcm")
  return c:decrypt(key, iv, ct_with_tag:sub(1, -TAG_LEN - 1), false, aad, ct_with_tag:sub(-TAG_LEN))
end

return _M
