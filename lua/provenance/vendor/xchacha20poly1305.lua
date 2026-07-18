-- XChaCha20-Poly1305 AEAD (RFC 8439 construction, 24-byte nonce), pure Lua.
--
-- Vendored/adapted from philanc/plc (Pure Lua Crypto), MIT.
--   upstream: https://github.com/philanc/plc  commit 9efed4113a1a5dcb12a1f526cd65561756e6d648
--   source files: plc/chacha20.lua, plc/poly1305.lua, plc/aead_chacha_poly.lua
--
-- LuaJIT (Neovim) adaptation:
--   * plc targets Lua 5.3+: native bitwise operators (& ~ << >> |), string.pack/
--     string.unpack, and 64-bit integers. Neovim's LuaJIT is Lua 5.1 semantics
--     (numbers are IEEE-754 doubles, has the `bit` library, no string.pack).
--   * ChaCha20 32-bit word ops -> LuaJIT `bit` library (bxor/rol/band/rshift) with
--     bit.tobit for mod-2^32 addition. LE packing/unpacking done by hand.
--   * Poly1305: plc's poly1305-donna 32-bit uses 26-bit limbs whose products/sums
--     reach ~2^58 and rely on Lua 5.3 64-bit integers. On LuaJIT doubles (53-bit
--     mantissa) that loses precision, so the d0..d4 multiply-accumulate is done in
--     an explicit 64-bit {hi,lo} representation (mul64 + carry), then reduced. The
--     limb schedule and reduction are otherwise plc's, unchanged.
--   * XChaCha20: plc's hchacha20 subkey derivation + IETF ChaCha20-Poly1305 over
--     nonce (0x00000000 || nonce[16:24]); 16-byte Poly1305 tag appended to
--     ciphertext (matching @noble/ciphers / libsodium framing).

local bit = require("bit")
local band, bxor, bor, bnot = bit.band, bit.bxor, bit.bor, bit.bnot
local lshift, rshift, rol = bit.lshift, bit.rshift, bit.rol
local tobit = bit.tobit
local byte, char, sub, rep = string.byte, string.char, string.sub, string.rep
local floor = math.floor
local concat = table.concat

local TWO32 = 4294967296

--------------------------------------------------------------------------------
-- little-endian word helpers

-- read u32 LE at 1-based index i, as a LuaJIT int32 (signed, mod 2^32)
local function u32le(s, i)
  local a, b, c, d = byte(s, i, i + 3)
  return tobit(a + b * 256 + c * 65536 + d * 16777216)
end

-- read u32 LE at 1-based index i, as an unsigned double in [0, 2^32)
local function u32u(s, i)
  local a, b, c, d = byte(s, i, i + 3)
  return a + b * 256 + c * 65536 + d * 16777216
end

-- pack an int32 word (LuaJIT signed) to 4 LE bytes
local function pack_i32(w)
  return char(band(w, 0xff), band(rshift(w, 8), 0xff),
    band(rshift(w, 16), 0xff), band(rshift(w, 24), 0xff))
end

-- pack an unsigned double word in [0,2^32) to 4 LE bytes
local function pack_u32(x)
  local b0 = x % 256; x = floor(x / 256)
  local b1 = x % 256; x = floor(x / 256)
  local b2 = x % 256; x = floor(x / 256)
  local b3 = x % 256
  return char(b0, b1, b2, b3)
end

--------------------------------------------------------------------------------
-- ChaCha20 (RFC 8439)

local function qround(st, x, y, z, w)
  local a, b, c, d = st[x], st[y], st[z], st[w]
  a = tobit(a + b); d = rol(bxor(d, a), 16)
  c = tobit(c + d); b = rol(bxor(b, c), 12)
  a = tobit(a + b); d = rol(bxor(d, a), 8)
  c = tobit(c + d); b = rol(bxor(b, c), 7)
  st[x], st[y], st[z], st[w] = a, b, c, d
end

-- key: int32[8], counter: int32, nonce: int32[3] -> keystream int32[16]
local function chacha20_block(key, counter, nonce)
  local st = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8],
    counter, nonce[1], nonce[2], nonce[3],
  }
  local w = {}
  for i = 1, 16 do w[i] = st[i] end
  for _ = 1, 10 do
    qround(w, 1, 5, 9, 13)
    qround(w, 2, 6, 10, 14)
    qround(w, 3, 7, 11, 15)
    qround(w, 4, 8, 12, 16)
    qround(w, 1, 6, 11, 16)
    qround(w, 2, 7, 12, 13)
    qround(w, 3, 8, 9, 14)
    qround(w, 4, 5, 10, 15)
  end
  for i = 1, 16 do st[i] = tobit(st[i] + w[i]) end
  return st
end

-- key: 32-byte string, counter: number, nonce: 12-byte string, pt: string
local function chacha20_xor(key, counter, nonce, pt)
  local keya = {}
  for i = 1, 8 do keya[i] = u32le(key, (i - 1) * 4 + 1) end
  local noncea = { u32le(nonce, 1), u32le(nonce, 5), u32le(nonce, 9) }
  local out = {}
  local n = #pt
  local ptidx = 1
  while ptidx <= n do
    local ks = chacha20_block(keya, tobit(counter), noncea)
    local blocklen = n - ptidx + 1
    if blocklen > 64 then blocklen = 64 end
    for j = 0, blocklen - 1 do
      local ksbyte = band(rshift(ks[floor(j / 4) + 1], (j % 4) * 8), 0xff)
      out[#out + 1] = char(bxor(byte(pt, ptidx + j), ksbyte))
    end
    ptidx = ptidx + 64
    counter = counter + 1
  end
  return concat(out)
end

-- HChaCha20: key 32B, nonce16 16B -> 32-byte subkey
local function hchacha20(key, nonce16)
  local st = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    u32le(key, 1), u32le(key, 5), u32le(key, 9), u32le(key, 13),
    u32le(key, 17), u32le(key, 21), u32le(key, 25), u32le(key, 29),
    u32le(nonce16, 1), u32le(nonce16, 5), u32le(nonce16, 9), u32le(nonce16, 13),
  }
  for _ = 1, 10 do
    qround(st, 1, 5, 9, 13)
    qround(st, 2, 6, 10, 14)
    qround(st, 3, 7, 11, 15)
    qround(st, 4, 8, 12, 16)
    qround(st, 1, 6, 11, 16)
    qround(st, 2, 7, 12, 13)
    qround(st, 3, 8, 9, 14)
    qround(st, 4, 5, 10, 15)
  end
  return pack_i32(st[1]) .. pack_i32(st[2]) .. pack_i32(st[3]) .. pack_i32(st[4]) ..
    pack_i32(st[13]) .. pack_i32(st[14]) .. pack_i32(st[15]) .. pack_i32(st[16])
end

--------------------------------------------------------------------------------
-- Poly1305 (RFC 8439) — 64-bit-safe port of plc's poly1305-donna 32-bit

-- full 64-bit product of two nonneg doubles < 2^32, returned as (hi, lo)
-- with value = hi*2^32 + lo, lo in [0, 2^32)
local function mul64(a, b)
  local ah = floor(a / 65536); local al = a - ah * 65536
  local bh = floor(b / 65536); local bl = b - bh * 65536
  local lo = al * bl
  local mid = ah * bl + al * bh
  local hi = ah * bh
  local mid_hi = floor(mid / 65536); local mid_lo = mid - mid_hi * 65536
  lo = lo + mid_lo * 65536
  hi = hi + mid_hi
  local carry = floor(lo / TWO32); lo = lo - carry * TWO32
  hi = hi + carry
  return hi, lo
end

local MASK26 = 67108864 -- 2^26

local function poly1305_auth(m, k)
  -- clamp r
  local r0 = band(u32u(k, 1), 0x3ffffff)
  local r1 = band(floor(u32u(k, 4) / 4), 0x3ffff03)
  local r2 = band(floor(u32u(k, 7) / 16), 0x3ffc0ff)
  local r3 = band(floor(u32u(k, 10) / 64), 0x3f03fff)
  local r4 = band(floor(u32u(k, 13) / 256), 0x00fffff)
  local s1, s2, s3, s4 = r1 * 5, r2 * 5, r3 * 5, r4 * 5
  local pad0, pad1, pad2, pad3 = u32u(k, 17), u32u(k, 21), u32u(k, 25), u32u(k, 29)

  local h0, h1, h2, h3, h4 = 0, 0, 0, 0, 0

  local function block(mm, idx, final)
    local hibit = final and 0 or 0x1000000 -- 1<<24
    h0 = h0 + band(u32u(mm, idx), 0x3ffffff)
    h1 = h1 + band(floor(u32u(mm, idx + 3) / 4), 0x3ffffff)
    h2 = h2 + band(floor(u32u(mm, idx + 6) / 16), 0x3ffffff)
    h3 = h3 + band(floor(u32u(mm, idx + 9) / 64), 0x3ffffff)
    h4 = h4 + bor(floor(u32u(mm, idx + 12) / 256), hibit)

    -- d_i = sum of h_j * (r or s), accumulated in 64-bit {hi,lo}
    local function madd(ah, al, x, y)
      local phi, plo = mul64(x, y)
      al = al + plo
      local c = floor(al / TWO32); al = al - c * TWO32
      return ah + phi + c, al
    end

    local d0h, d0l = madd(0, 0, h0, r0)
    d0h, d0l = madd(d0h, d0l, h1, s4)
    d0h, d0l = madd(d0h, d0l, h2, s3)
    d0h, d0l = madd(d0h, d0l, h3, s2)
    d0h, d0l = madd(d0h, d0l, h4, s1)

    local d1h, d1l = madd(0, 0, h0, r1)
    d1h, d1l = madd(d1h, d1l, h1, r0)
    d1h, d1l = madd(d1h, d1l, h2, s4)
    d1h, d1l = madd(d1h, d1l, h3, s3)
    d1h, d1l = madd(d1h, d1l, h4, s2)

    local d2h, d2l = madd(0, 0, h0, r2)
    d2h, d2l = madd(d2h, d2l, h1, r1)
    d2h, d2l = madd(d2h, d2l, h2, r0)
    d2h, d2l = madd(d2h, d2l, h3, s4)
    d2h, d2l = madd(d2h, d2l, h4, s3)

    local d3h, d3l = madd(0, 0, h0, r3)
    d3h, d3l = madd(d3h, d3l, h1, r2)
    d3h, d3l = madd(d3h, d3l, h2, r1)
    d3h, d3l = madd(d3h, d3l, h3, r0)
    d3h, d3l = madd(d3h, d3l, h4, s4)

    local d4h, d4l = madd(0, 0, h0, r4)
    d4h, d4l = madd(d4h, d4l, h1, r3)
    d4h, d4l = madd(d4h, d4l, h2, r2)
    d4h, d4l = madd(d4h, d4l, h3, r1)
    d4h, d4l = madd(d4h, d4l, h4, r0)

    -- >>26 of a 64-bit {hi,lo}: hi*2^6 + floor(lo/2^26)
    local function shr26(dh, dl) return dh * 64 + floor(dl / MASK26) end
    -- add a scalar c (< 2^41) to a 64-bit {hi,lo}
    local function addc(dh, dl, c)
      local chi = floor(c / TWO32); local clo = c - chi * TWO32
      dl = dl + clo
      local cc = floor(dl / TWO32); dl = dl - cc * TWO32
      return dh + chi + cc, dl
    end

    local c
    c = shr26(d0h, d0l); h0 = d0l % MASK26
    d1h, d1l = addc(d1h, d1l, c); c = shr26(d1h, d1l); h1 = d1l % MASK26
    d2h, d2l = addc(d2h, d2l, c); c = shr26(d2h, d2l); h2 = d2l % MASK26
    d3h, d3l = addc(d3h, d3l, c); c = shr26(d3h, d3l); h3 = d3l % MASK26
    d4h, d4l = addc(d4h, d4l, c); c = shr26(d4h, d4l); h4 = d4l % MASK26
    h0 = h0 + c * 5; c = floor(h0 / MASK26); h0 = h0 % MASK26
    h1 = h1 + c
  end

  -- full 16-byte blocks
  local n = #m
  local idx = 1
  while n - idx + 1 >= 16 do
    block(m, idx, false)
    idx = idx + 16
  end
  -- final partial block (with 0x01 pad byte)
  local rem = n - idx + 1
  if rem > 0 then
    local buf = sub(m, idx) .. "\x01" .. rep("\0", 16 - rem - 1)
    block(buf, 1, true)
  end

  -- finish: fully carry h
  local c
  c = floor(h1 / MASK26); h1 = h1 % MASK26
  h2 = h2 + c; c = floor(h2 / MASK26); h2 = h2 % MASK26
  h3 = h3 + c; c = floor(h3 / MASK26); h3 = h3 % MASK26
  h4 = h4 + c; c = floor(h4 / MASK26); h4 = h4 % MASK26
  h0 = h0 + c * 5; c = floor(h0 / MASK26); h0 = h0 % MASK26
  h1 = h1 + c

  -- compute h + -p
  local g0 = h0 + 5; c = floor(g0 / MASK26); g0 = g0 % MASK26
  local g1 = h1 + c; c = floor(g1 / MASK26); g1 = g1 % MASK26
  local g2 = h2 + c; c = floor(g2 / MASK26); g2 = g2 % MASK26
  local g3 = h3 + c; c = floor(g3 / MASK26); g3 = g3 % MASK26
  local g4 = h4 + c - 0x4000000 -- (1<<26); may be negative

  -- select h if h < p, else h + -p. mask = (g4>>31)-1 (all ones if g4 negative)
  -- g4 negative => borrow => h < p => keep h.
  local keep_h
  if g4 < 0 then keep_h = true else keep_h = false end
  if not keep_h then
    -- g4 masked to 26 bits
    g4 = band(g4, 0x3ffffff)
    h0, h1, h2, h3, h4 = g0, g1, g2, g3, g4
  end

  -- h = h % 2^128 : pack 5x26-bit limbs into 4x32-bit words (unsigned doubles)
  local w0 = (h0 + h1 * MASK26) % TWO32
  local w1 = (floor(h1 / 64) + h2 * 1048576) % TWO32  -- h1>>6 | h2<<20
  local w2 = (floor(h2 / 4096) + h3 * 16384) % TWO32  -- h2>>12 | h3<<14
  local w3 = (floor(h3 / 262144) + h4 * 256) % TWO32  -- h3>>18 | h4<<8

  -- mac = (h + pad) % 2^128
  local f
  f = w0 + pad0; w0 = f % TWO32
  f = w1 + pad1 + floor(f / TWO32); w1 = f % TWO32
  f = w2 + pad2 + floor(f / TWO32); w2 = f % TWO32
  f = w3 + pad3 + floor(f / TWO32); w3 = f % TWO32

  return pack_u32(w0) .. pack_u32(w1) .. pack_u32(w2) .. pack_u32(w3)
end

--------------------------------------------------------------------------------
-- AEAD combiner (RFC 8439 §2.8) over XChaCha20

local function pad16(s)
  local r = #s % 16
  if r == 0 then return "" end
  return rep("\0", 16 - r)
end

local function le64(n)
  -- n < 2^53; low 8 bytes little-endian
  local out = {}
  for _ = 1, 8 do
    out[#out + 1] = char(n % 256)
    n = floor(n / 256)
  end
  return concat(out)
end

local M = {}

-- encrypt(key32, nonce24, plaintext, aad?) -> ciphertext .. 16-byte tag
function M.encrypt(key, nonce, plaintext, aad)
  assert(#key == 32, "key must be 32 bytes")
  assert(#nonce == 24, "nonce must be 24 bytes")
  aad = aad or ""
  local subkey = hchacha20(key, sub(nonce, 1, 16))
  local nonce12 = "\0\0\0\0" .. sub(nonce, 17, 24)
  local otk = sub(chacha20_xor(subkey, 0, nonce12, rep("\0", 32)), 1, 32)
  local ct = chacha20_xor(subkey, 1, nonce12, plaintext)
  local mac_data = aad .. pad16(aad) .. ct .. pad16(ct) .. le64(#aad) .. le64(#ct)
  local tag = poly1305_auth(mac_data, otk)
  return ct .. tag
end

-- decrypt(key32, nonce24, ct_with_tag, aad?) -> plaintext | nil (nil on tag fail)
function M.decrypt(key, nonce, ct_with_tag, aad)
  assert(#key == 32, "key must be 32 bytes")
  assert(#nonce == 24, "nonce must be 24 bytes")
  if #ct_with_tag < 16 then return nil end
  aad = aad or ""
  local ct = sub(ct_with_tag, 1, #ct_with_tag - 16)
  local tag = sub(ct_with_tag, #ct_with_tag - 15)
  local subkey = hchacha20(key, sub(nonce, 1, 16))
  local nonce12 = "\0\0\0\0" .. sub(nonce, 17, 24)
  local otk = sub(chacha20_xor(subkey, 0, nonce12, rep("\0", 32)), 1, 32)
  local mac_data = aad .. pad16(aad) .. ct .. pad16(ct) .. le64(#aad) .. le64(#ct)
  local want = poly1305_auth(mac_data, otk)
  -- constant-time-ish compare
  if #want ~= #tag then return nil end
  local diff = 0
  for i = 1, 16 do diff = bor(diff, bxor(byte(want, i), byte(tag, i))) end
  if diff ~= 0 then return nil end
  return chacha20_xor(subkey, 1, nonce12, ct)
end

return M
