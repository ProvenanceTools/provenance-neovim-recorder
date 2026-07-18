local session_keys = require("provenance.core.session_keys")
local ed25519 = require("provenance.core.ed25519")

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

describe("core.session_keys generate", function()
  it("produces a fresh ed25519 keypair whose pubkey matches its privkey", function()
    local kp = session_keys.generate()
    assert.equals(32, #kp.private_key)
    assert.equals(64, #kp.public_key_hex)
    assert.equals(kp.public_key_hex, ed25519.to_hex(ed25519.public_key_of(kp.private_key)))
  end)

  it("produces distinct keys across calls", function()
    assert.are_not.equals(session_keys.generate().public_key_hex, session_keys.generate().public_key_hex)
  end)
end)

describe("core.session_keys encrypt/decrypt round-trip", function()
  it("decrypt(encrypt(priv)) == priv with the same manifest sig", function()
    local kp = session_keys.generate()
    local sig = string.rep("ab", 64) -- 128-hex manifest sig
    local enc = session_keys.encrypt_privkey(kp.private_key, sig)
    assert.equals("xchacha20-poly1305-hkdf-sha256-v1", enc.algorithm)
    assert.equals("provenance-session-key-v1", enc.info)
    assert.equals(16, #from_hex(enc.salt))
    assert.equals(24, #from_hex(enc.nonce))
    assert.equals(48, #from_hex(enc.ciphertext)) -- 32 privkey + 16 tag
    assert.equals(kp.private_key, session_keys.decrypt_privkey(enc, sig))
  end)

  it("random salt/nonce differ across calls", function()
    local kp = session_keys.generate()
    local sig = string.rep("cd", 64)
    local a = session_keys.encrypt_privkey(kp.private_key, sig)
    local b = session_keys.encrypt_privkey(kp.private_key, sig)
    assert.are_not.equals(a.nonce, b.nonce)
    assert.are_not.equals(a.salt, b.salt)
    assert.are_not.equals(a.ciphertext, b.ciphertext)
  end)

  it("wrong manifest sig on decrypt returns nil (auth-tag failure)", function()
    local kp = session_keys.generate()
    local enc = session_keys.encrypt_privkey(kp.private_key, string.rep("11", 64))
    assert.is_nil(session_keys.decrypt_privkey(enc, string.rep("22", 64)))
  end)

  it("tampered ciphertext returns nil", function()
    local kp = session_keys.generate()
    local sig = string.rep("ef", 64)
    local enc = session_keys.encrypt_privkey(kp.private_key, sig)
    local raw = from_hex(enc.ciphertext)
    enc.ciphertext = to_hex(raw:sub(1, -2) .. string.char((raw:byte(#raw) + 1) % 256))
    assert.is_nil(session_keys.decrypt_privkey(enc, sig))
  end)

  it("does not throw on malformed EncryptedPrivkey", function()
    assert.is_nil(session_keys.decrypt_privkey(nil, string.rep("00", 64)))
    assert.is_nil(session_keys.decrypt_privkey({ algorithm = "nope" }, string.rep("00", 64)))
  end)
end)

describe("core.session_keys cross-language vector (session-key.json)", function()
  local fx = load_session_fixture()

  it("reproduces the pinned ciphertext_hex (AEAD framing == @noble/ciphers)", function()
    local enc = session_keys.encrypt_privkey(
      from_hex(fx.privkey_hex), fx.manifest_sig, from_hex(fx.salt_hex), from_hex(fx.nonce_hex))
    assert.equals(fx.ciphertext_hex, enc.ciphertext)
    assert.equals(fx.salt_hex, enc.salt)
    assert.equals(fx.nonce_hex, enc.nonce)
    assert.equals(fx.algorithm, enc.algorithm)
  end)

  it("decrypts the pinned vector back to the private key", function()
    local enc = {
      algorithm = fx.algorithm,
      salt = fx.salt_hex,
      nonce = fx.nonce_hex,
      ciphertext = fx.ciphertext_hex,
      info = fx.info,
    }
    assert.equals(fx.privkey_hex, to_hex(session_keys.decrypt_privkey(enc, fx.manifest_sig)))
  end)
end)
