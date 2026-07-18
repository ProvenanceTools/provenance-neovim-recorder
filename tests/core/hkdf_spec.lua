local hkdf = require("provenance.core.hkdf")

local function from_hex(h)
  return (h:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end
local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_session_fixture()
  local dir = this_file_dir() .. "/../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. "session-key.json"), "\n"))
end

describe("core.hkdf HMAC-SHA256 (RFC 2104)", function()
  -- RFC 4231 Test Case 2 (HMAC-SHA256): key "Jefe", data "what do ya want for nothing?"
  it("matches the RFC 4231 case 2 vector", function()
    local mac = hkdf.hmac_sha256("Jefe", "what do ya want for nothing?")
    assert.equals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", to_hex(mac))
  end)

  it("returns raw 32 bytes", function()
    assert.equals(32, #hkdf.hmac_sha256("k", "m"))
  end)

  it("handles keys longer than the 64-byte block (RFC 4231 case 6)", function()
    local key = string.rep("\xaa", 131)
    local data = "Test Using Larger Than Block-Size Key - Hash Key First"
    local mac = hkdf.hmac_sha256(key, data)
    assert.equals("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", to_hex(mac))
  end)
end)

describe("core.hkdf HKDF-SHA256 (RFC 5869)", function()
  it("matches RFC 5869 Test Case 1", function()
    local ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    local salt = from_hex("000102030405060708090a0b0c")
    local info = from_hex("f0f1f2f3f4f5f6f7f8f9")
    local okm = hkdf.derive(ikm, salt, info, 42)
    assert.equals(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
      to_hex(okm))
  end)

  it("matches RFC 5869 Test Case 3 (empty salt + empty info)", function()
    local ikm = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    local okm = hkdf.derive(ikm, "", "", 42)
    assert.equals(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
      to_hex(okm))
  end)

  it("produces exactly `len` bytes", function()
    assert.equals(16, #hkdf.derive("ikm", "salt", "info", 16))
    assert.equals(80, #hkdf.derive("ikm", "salt", "info", 80))
  end)

  it("reproduces the session-key.json hkdf_key_hex (pins HMAC+HKDF independently)", function()
    local fx = load_session_fixture()
    local key = hkdf.derive(from_hex(fx.manifest_sig), from_hex(fx.salt_hex), fx.info, 32)
    assert.equals(fx.hkdf_key_hex, to_hex(key))
  end)
end)
