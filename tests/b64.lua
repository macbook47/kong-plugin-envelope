-- Minimal pure-Lua base64 (standard and URL-safe) so the offline tests need no extra library.
local M = {}
local STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local DEC = {}
for i = 1, 64 do DEC[STD:sub(i, i)] = i - 1 end

function M.encode(s)
  local out = {}
  for i = 1, #s, 3 do
    local a, b, c = s:byte(i, i + 2)
    local n = a * 65536 + (b or 0) * 256 + (c or 0)
    local c1, c2 = math.floor(n / 262144) % 64, math.floor(n / 4096) % 64
    local c3, c4 = math.floor(n / 64) % 64, n % 64
    out[#out + 1] = STD:sub(c1 + 1, c1 + 1) .. STD:sub(c2 + 1, c2 + 1)
      .. (b and STD:sub(c3 + 1, c3 + 1) or "=") .. (c and STD:sub(c4 + 1, c4 + 1) or "=")
  end
  return table.concat(out)
end

function M.decode(s)
  if type(s) ~= "string" or #s % 4 ~= 0 or s:find("[^%w%+/=]") then return nil end
  local out = {}
  for i = 1, #s, 4 do
    local q = { s:byte(i, i + 3) }
    local v, pad = 0, 0
    for j = 1, 4 do
      local ch = string.char(q[j])
      if ch == "=" then pad = pad + 1; v = v * 64
      else local d = DEC[ch]; if not d then return nil end; v = v * 64 + d end
    end
    local bytes = string.char(math.floor(v / 65536) % 256, math.floor(v / 256) % 256, v % 256)
    out[#out + 1] = bytes:sub(1, 3 - pad)
  end
  return table.concat(out)
end

function M.encode_url(s) return (M.encode(s):gsub("+", "-"):gsub("/", "_"):gsub("=", "")) end
function M.decode_url(s)
  s = s:gsub("-", "+"):gsub("_", "/")
  return M.decode(s .. string.rep("=", (4 - #s % 4) % 4))
end
return M
