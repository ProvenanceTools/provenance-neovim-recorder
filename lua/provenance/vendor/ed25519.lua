-- Vendored pure-Lua ed25519 (RFC 8032, deterministic) + SHA-512.
--
-- Upstream: TweetNaCl.js (dchest/tweetnacl-js), file nacl.js, Public Domain.
-- Ported to LuaJIT for provnvim. Faithful transliteration of nacl.js's ed25519
-- (crypto_sign / crypto_sign_open / crypto_sign_keypair) + its bundled SHA-512
-- (crypto_hash / crypto_hashblocks). See THIRD-PARTY-NOTICES.txt.
--
-- Adaptations from the JS source:
--   * Uint8Array / Float64Array -> 0-indexed Lua tables of numbers. LuaJIT
--     numbers are IEEE-754 doubles exactly like JS numbers, so the field
--     arithmetic (gf limbs, M, car25519, modL) transliterates 1:1 using
--     math.floor for the `Math.floor` / arithmetic `>>` on wide values.
--   * `subarray(off)` views -> explicit integer offset parameters.
--   * SHA-512 64-bit words: the `u64{hi,lo}` object -> a plain {hi=,lo=} table
--     holding UNSIGNED 32-bit halves (0..2^32-1). add64 stays in arithmetic
--     (16-bit lane splits); xor64/shr64/R use the LuaJIT `bit` library,
--     normalized back to unsigned via u32().
--   * `bit32`/JS operators: `^ & | ~ << >>> ` on int32 values -> LuaJIT `bit`
--     (bxor/band/bor/bnot/lshift/rshift). Arithmetic `>>` on signed field
--     values -> math.floor division (matches two's-complement arithmetic shift
--     within int32 range). `&255` on possibly-negative values -> mod 256.

local bit = require("bit")
local band, bor, bxor, bnot = bit.band, bit.bor, bit.bxor, bit.bnot
local lshift, rshift, arshift = bit.lshift, bit.rshift, bit.arshift
local floor = math.floor

local TWO32 = 4294967296

local function u32(x)
  -- Normalize a bit-op result (signed int32) to unsigned 0..2^32-1.
  x = x % TWO32
  if x < 0 then x = x + TWO32 end
  return x
end

-- ---------- byte / gf helpers ----------

local function new_bytes(n)
  local t = {}
  for i = 0, n - 1 do t[i] = 0 end
  return t
end

local function gf(init)
  local r = {}
  for i = 0, 15 do r[i] = 0 end
  if init then
    for i = 0, #init do r[i] = init[i] end -- init is 0-indexed table
  end
  return r
end

-- 0-indexed constant tables (mirror the JS gf([...]) initializers)
local function gfc(list) -- list given 1-indexed for readability
  local r = {}
  for i = 0, 15 do r[i] = list[i + 1] or 0 end
  return r
end

local gf0 = gf()
local gf1 = gfc({1})
local D = gfc({0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203})
local D2 = gfc({0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406})
local X = gfc({0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169})
local Y = gfc({0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666})
local I = gfc({0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83})

-- ---------- SHA-512 ----------

local function U(h, l) return { hi = h, lo = l } end

local function dl64(x, i)
  local h = x[i] * 16777216 + x[i + 1] * 65536 + x[i + 2] * 256 + x[i + 3]
  local l = x[i + 4] * 16777216 + x[i + 5] * 65536 + x[i + 6] * 256 + x[i + 7]
  return U(h, l)
end

local function ts64(x, i, u)
  local hi, lo = u.hi, u.lo
  x[i]     = floor(hi / 16777216) % 256
  x[i + 1] = floor(hi / 65536) % 256
  x[i + 2] = floor(hi / 256) % 256
  x[i + 3] = hi % 256
  x[i + 4] = floor(lo / 16777216) % 256
  x[i + 5] = floor(lo / 65536) % 256
  x[i + 6] = floor(lo / 256) % 256
  x[i + 7] = lo % 256
end

local function add64(list)
  local a, b, c, d = 0, 0, 0, 0
  for i = 1, #list do
    local l, h = list[i].lo, list[i].hi
    a = a + (l % 65536)
    b = b + floor(l / 65536)
    c = c + (h % 65536)
    d = d + floor(h / 65536)
  end
  b = b + floor(a / 65536)
  c = c + floor(b / 65536)
  d = d + floor(c / 65536)
  local lo = (a % 65536) + (b % 65536) * 65536
  local hi = (c % 65536) + (d % 65536) * 65536
  return U(hi, lo)
end

local function shr64(x, c)
  return U(rshift(x.hi, c), u32(bor(rshift(x.lo, c), lshift(x.hi, 32 - c))))
end

local function xor64(list)
  local l, h = 0, 0
  for i = 1, #list do
    l = bxor(l, list[i].lo)
    h = bxor(h, list[i].hi)
  end
  return U(u32(h), u32(l))
end

local function R(x, c)
  local h, l
  local c1 = 32 - c
  if c < 32 then
    h = bor(rshift(x.hi, c), lshift(x.lo, c1))
    l = bor(rshift(x.lo, c), lshift(x.hi, c1))
  else
    h = bor(rshift(x.lo, c), lshift(x.hi, c1))
    l = bor(rshift(x.hi, c), lshift(x.lo, c1))
  end
  return U(u32(h), u32(l))
end

local function Ch(x, y, z)
  local h = bxor(band(x.hi, y.hi), band(bnot(x.hi), z.hi))
  local l = bxor(band(x.lo, y.lo), band(bnot(x.lo), z.lo))
  return U(u32(h), u32(l))
end

local function Maj(x, y, z)
  local h = bxor(bxor(band(x.hi, y.hi), band(x.hi, z.hi)), band(y.hi, z.hi))
  local l = bxor(bxor(band(x.lo, y.lo), band(x.lo, z.lo)), band(y.lo, z.lo))
  return U(u32(h), u32(l))
end

local function Sigma0(x) return xor64({ R(x, 28), R(x, 34), R(x, 39) }) end
local function Sigma1(x) return xor64({ R(x, 14), R(x, 18), R(x, 41) }) end
local function sigma0(x) return xor64({ R(x, 1), R(x, 8), shr64(x, 7) }) end
local function sigma1(x) return xor64({ R(x, 19), R(x, 61), shr64(x, 6) }) end

local K_raw = {
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
}
local K = {}
for i = 0, 79 do K[i] = U(K_raw[2 * i + 1], K_raw[2 * i + 2]) end

local iv = {
  [0] = 0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
  0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
  0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,
  0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
  0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1,
  0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
  0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
  0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79,
}

local function crypto_hashblocks(x, m, moff, n)
  local z, b, a, w = {}, {}, {}, {}
  for i = 0, 7 do
    local v = dl64(x, 8 * i)
    z[i] = v
    a[i] = U(v.hi, v.lo)
  end

  local pos = 0
  while n >= 128 do
    for i = 0, 15 do w[i] = dl64(m, moff + 8 * i + pos) end
    for i = 0, 79 do
      for j = 0, 7 do b[j] = a[j] end
      local t = add64({ a[7], Sigma1(a[4]), Ch(a[4], a[5], a[6]), K[i], w[i % 16] })
      b[7] = add64({ t, Sigma0(a[0]), Maj(a[0], a[1], a[2]) })
      b[3] = add64({ b[3], t })
      for j = 0, 7 do a[(j + 1) % 8] = b[j] end
      if i % 16 == 15 then
        for j = 0, 15 do
          w[j] = add64({ w[j], w[(j + 9) % 16], sigma0(w[(j + 1) % 16]), sigma1(w[(j + 14) % 16]) })
        end
      end
    end

    for i = 0, 7 do
      a[i] = add64({ a[i], z[i] })
      z[i] = a[i]
    end

    pos = pos + 128
    n = n - 128
  end

  for i = 0, 7 do ts64(x, 8 * i, z[i]) end
  return n
end

local function crypto_hash(out, m, moff, n)
  local h = new_bytes(64)
  local x = new_bytes(256)
  local b = n

  for i = 0, 63 do h[i] = iv[i] end

  crypto_hashblocks(h, m, moff, n)
  n = n % 128

  for i = 0, 255 do x[i] = 0 end
  for i = 0, n - 1 do x[i] = m[moff + b - n + i] end
  x[n] = 128

  n = 256 - 128 * (n < 112 and 1 or 0)
  x[n - 9] = 0
  ts64(x, n - 8, U(floor(b / 0x20000000) % TWO32, (b * 8) % TWO32))
  crypto_hashblocks(h, x, 0, n)

  for i = 0, 63 do out[i] = h[i] end
  return 0
end

-- ---------- field arithmetic (gf) ----------

local function set25519(r, a)
  for i = 0, 15 do r[i] = a[i] end
end

local function car25519(o)
  for i = 0, 15 do
    o[i] = o[i] + 65536
    local c = floor(o[i] / 65536)
    -- JS: o[(i+1)*(i<15?1:0)] += c-1 + 37*(c-1)*(i===15?1:0)
    local idx = (i + 1) * (i < 15 and 1 or 0)
    o[idx] = o[idx] + (c - 1 + 37 * (c - 1) * (i == 15 and 1 or 0))
    o[i] = o[i] - c * 65536
  end
end

local function sel25519(p, q, b)
  local c = bnot(b - 1)
  for i = 0, 15 do
    local t = band(c, bxor(p[i], q[i]))
    p[i] = bxor(p[i], t)
    q[i] = bxor(q[i], t)
  end
end

local function pack25519(o, n)
  local m, t = gf(), gf()
  for i = 0, 15 do t[i] = n[i] end
  car25519(t)
  car25519(t)
  car25519(t)
  for _ = 0, 1 do
    m[0] = t[0] - 0xffed
    for i = 1, 14 do
      m[i] = t[i] - 0xffff - band(arshift(m[i - 1], 16), 1)
      m[i - 1] = band(m[i - 1], 0xffff)
    end
    m[15] = t[15] - 0x7fff - band(arshift(m[14], 16), 1)
    local b = band(arshift(m[15], 16), 1)
    m[14] = band(m[14], 0xffff)
    sel25519(t, m, 1 - b)
  end
  for i = 0, 15 do
    o[2 * i] = band(t[i], 0xff)
    o[2 * i + 1] = arshift(t[i], 8)
  end
end

local function crypto_verify_32(x, xi, y, yi)
  local d = 0
  for i = 0, 31 do d = bor(d, bxor(x[xi + i], y[yi + i])) end
  -- return (1 & ((d - 1) >>> 8)) - 1;
  return band(1, rshift(u32(d) - 1, 8)) - 1
end

local function neq25519(a, b)
  local c, d = new_bytes(32), new_bytes(32)
  pack25519(c, a)
  pack25519(d, b)
  return crypto_verify_32(c, 0, d, 0)
end

local function par25519(a)
  local d = new_bytes(32)
  pack25519(d, a)
  return band(d[0], 1)
end

local function unpack25519(o, n)
  for i = 0, 15 do o[i] = n[2 * i] + n[2 * i + 1] * 256 end
  o[15] = band(o[15], 0x7fff)
end

local function A(o, a, b)
  for i = 0, 15 do o[i] = a[i] + b[i] end
end

local function Z(o, a, b)
  for i = 0, 15 do o[i] = a[i] - b[i] end
end

local function M(o, a, b)
  local t = {}
  for i = 0, 30 do t[i] = 0 end
  for i = 0, 15 do
    for j = 0, 15 do
      t[i + j] = t[i + j] + a[i] * b[j]
    end
  end
  for i = 0, 14 do
    t[i] = t[i] + 38 * t[i + 16]
  end
  for i = 0, 15 do o[i] = t[i] end
  car25519(o)
  car25519(o)
end

local function S(o, a)
  M(o, a, a)
end

local function inv25519(o, i)
  local c = gf()
  for a = 0, 15 do c[a] = i[a] end
  for a = 253, 0, -1 do
    S(c, c)
    if a ~= 2 and a ~= 4 then M(c, c, i) end
  end
  for a = 0, 15 do o[a] = c[a] end
end

local function pow2523(o, i)
  local c = gf()
  for a = 0, 15 do c[a] = i[a] end
  for a = 250, 0, -1 do
    S(c, c)
    if a ~= 1 then M(c, c, i) end
  end
  for a = 0, 15 do o[a] = c[a] end
end

-- ---------- ed25519 group ops ----------

local function add(p, q)
  local a, b, c, d, e, f, g, h, t = gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf()
  Z(a, p[1], p[0])
  Z(t, q[1], q[0])
  M(a, a, t)
  A(b, p[0], p[1])
  A(t, q[0], q[1])
  M(b, b, t)
  M(c, p[3], q[3])
  M(c, c, D2)
  M(d, p[2], q[2])
  A(d, d, d)
  Z(e, b, a)
  Z(f, d, c)
  A(g, d, c)
  A(h, b, a)
  M(p[0], e, f)
  M(p[1], h, g)
  M(p[2], g, f)
  M(p[3], e, h)
end

local function cswap(p, q, b)
  for i = 0, 3 do
    sel25519(p[i], q[i], b)
  end
end

local function pack(r, p)
  local tx, ty, zi = gf(), gf(), gf()
  inv25519(zi, p[2])
  M(tx, p[0], zi)
  M(ty, p[1], zi)
  pack25519(r, ty)
  r[31] = bxor(r[31], lshift(par25519(tx), 7))
end

-- ed25519 points are 0-indexed 4-tuples of gf (extended coords).
local function points4()
  return { [0] = gf(), gf(), gf(), gf() }
end

local function scalarmult(p, q, s)
  set25519(p[0], gf0)
  set25519(p[1], gf1)
  set25519(p[2], gf1)
  set25519(p[3], gf0)
  for i = 255, 0, -1 do
    -- s bytes are 0..255; logical right shift by (i%8), take low bit.
    local b = band(rshift(s[floor(i / 8)], (i % 8)), 1)
    cswap(p, q, b)
    add(q, p)
    add(p, p)
    cswap(p, q, b)
  end
end

local function scalarbase(p, s)
  local q = points4()
  set25519(q[0], X)
  set25519(q[1], Y)
  set25519(q[2], gf1)
  M(q[3], X, Y)
  scalarmult(p, q, s)
end

-- ---------- scalar reduction ----------

local L = { [0] = 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 }

local function modL(r, roff, x)
  local carry
  for i = 63, 32, -1 do
    carry = 0
    local j = i - 32
    local k = i - 12
    while j < k do
      x[j] = x[j] + carry - 16 * x[i] * L[j - (i - 32)]
      carry = floor((x[j] + 128) / 256)
      x[j] = x[j] - carry * 256
      j = j + 1
    end
    x[j] = x[j] + carry
    x[i] = 0
  end
  carry = 0
  for j = 0, 31 do
    x[j] = x[j] + carry - floor(x[31] / 16) * L[j]
    carry = floor(x[j] / 256)
    x[j] = x[j] - carry * 256
  end
  for j = 0, 31 do x[j] = x[j] - carry * L[j] end
  for i = 0, 31 do
    x[i + 1] = x[i + 1] + floor(x[i] / 256)
    r[roff + i] = x[i] - floor(x[i] / 256) * 256
  end
end

local function reduce(r)
  local x = {}
  for i = 0, 63 do x[i] = r[i] end
  for i = 0, 63 do r[i] = 0 end
  modL(r, 0, x)
end

-- ---------- keypair / sign / verify ----------

local function crypto_sign_keypair_from_seed(pk, sk)
  -- sk[0..31] holds the seed on entry.
  local d = new_bytes(64)
  local p = points4()
  crypto_hash(d, sk, 0, 32)
  d[0] = band(d[0], 248)
  d[31] = band(d[31], 127)
  d[31] = bor(d[31], 64)
  scalarbase(p, d)
  pack(pk, p)
  for i = 0, 31 do sk[i + 32] = pk[i] end
  return 0
end

-- crypto_sign: sm gets [R(32) || S(32) || message]; returns sm[0..63] as sig.
local function crypto_sign(sm, m, n, sk)
  local d, h, r = new_bytes(64), new_bytes(64), new_bytes(64)
  local x = {}
  local p = points4()

  crypto_hash(d, sk, 0, 32)
  d[0] = band(d[0], 248)
  d[31] = band(d[31], 127)
  d[31] = bor(d[31], 64)

  local smlen = n + 64
  for i = 0, n - 1 do sm[64 + i] = m[i] end
  for i = 0, 31 do sm[32 + i] = d[32 + i] end

  crypto_hash(r, sm, 32, n + 32)
  reduce(r)
  scalarbase(p, r)
  pack(sm, p)

  for i = 32, 63 do sm[i] = sk[i] end
  crypto_hash(h, sm, 0, n + 64)
  reduce(h)

  for i = 0, 63 do x[i] = 0 end
  for i = 0, 31 do x[i] = r[i] end
  for i = 0, 31 do
    for j = 0, 31 do
      x[i + j] = x[i + j] + h[i] * d[j]
    end
  end

  modL(sm, 32, x)
  return smlen
end

local function unpackneg(r, p)
  local t, chk, num, den, den2, den4, den6 = gf(), gf(), gf(), gf(), gf(), gf(), gf()

  set25519(r[2], gf1)
  unpack25519(r[1], p)
  S(num, r[1])
  M(den, num, D)
  Z(num, num, r[2])
  A(den, r[2], den)

  S(den2, den)
  S(den4, den2)
  M(den6, den4, den2)
  M(t, den6, num)
  M(t, t, den)

  pow2523(t, t)
  M(t, t, num)
  M(t, t, den)
  M(t, t, den)
  M(r[0], t, den)

  S(chk, r[0])
  M(chk, chk, den)
  if neq25519(chk, num) ~= 0 then M(r[0], r[0], I) end

  S(chk, r[0])
  M(chk, chk, den)
  if neq25519(chk, num) ~= 0 then return -1 end

  if par25519(r[0]) == arshift(p[31], 7) then Z(r[0], gf0, r[0]) end

  M(r[3], r[0], r[1])
  return 0
end

-- crypto_sign_open: returns 0 if signature valid, -1 otherwise.
-- sm[0..63] signature, m is message bytes (length n), pk pubkey.
local function crypto_sign_verify(sig, m, n, pk)
  local t = new_bytes(32)
  local h = new_bytes(64)
  local p = points4()
  local q = points4()

  if unpackneg(q, pk) ~= 0 then return false end

  -- build h = SHA512(R || A || M)
  local buf = new_bytes(32 + 32 + n)
  for i = 0, 31 do buf[i] = sig[i] end
  for i = 0, 31 do buf[32 + i] = pk[i] end
  for i = 0, n - 1 do buf[64 + i] = m[i] end
  crypto_hash(h, buf, 0, 64 + n)
  reduce(h)
  scalarmult(p, q, h)

  local s = {}
  for i = 0, 31 do s[i] = sig[32 + i] end
  scalarbase(q, s)
  add(p, q)
  pack(t, p)

  if crypto_verify_32(sig, 0, t, 0) ~= 0 then return false end
  return true
end

-- ---------- public API (raw byte-array level) ----------
-- All inputs/outputs are 0-indexed Lua tables of byte numbers.

local Vendor = {}

-- seed: 0-indexed table of 32 bytes. Returns pk(32), sk(64: seed||pk).
function Vendor.keypair_from_seed(seed)
  local sk = new_bytes(64)
  for i = 0, 31 do sk[i] = seed[i] end
  local pk = new_bytes(32)
  crypto_sign_keypair_from_seed(pk, sk)
  return pk, sk
end

-- seed(32 bytes), msg (0-indexed table, length mlen). Returns sig (64 bytes).
function Vendor.sign(seed, msg, mlen)
  local sk = new_bytes(64)
  for i = 0, 31 do sk[i] = seed[i] end
  local pk = new_bytes(32)
  crypto_sign_keypair_from_seed(pk, sk)
  local sm = new_bytes(mlen + 64)
  crypto_sign(sm, msg, mlen, sk)
  local sig = new_bytes(64)
  for i = 0, 63 do sig[i] = sm[i] end
  return sig
end

-- sig(64), msg(mlen), pk(32) -> boolean
function Vendor.verify(sig, msg, mlen, pk)
  return crypto_sign_verify(sig, msg, mlen, pk)
end

return Vendor
