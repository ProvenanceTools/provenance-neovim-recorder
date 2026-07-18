local ed = require("provenance.core.ed25519")

-- Locate the shared conformance fixtures dir (see conformance_spec for why
-- debug.getinfo is used rather than <sfile> under plenary's loadfile runner).
local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_ed25519_fixture()
  local dir = this_file_dir() .. "/../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. "ed25519.json"), "\n"))
end

describe("core.ed25519 hex helpers", function()
  it("round-trips bytes through hex (lowercase)", function()
    local raw = ed.from_hex("00ff10ea")
    assert.equals(4, #raw)
    assert.equals("00ff10ea", ed.to_hex(raw))
  end)
end)

describe("core.ed25519 round-trip", function()
  it("generate -> sign -> verify is true", function()
    local priv, pub_hex = ed.generate_keypair()
    assert.equals(32, #priv)
    assert.equals(64, #pub_hex)
    local msg = "the quick brown fox"
    local sig = ed.sign(msg, priv)
    assert.equals(64, #sig)
    assert.is_true(ed.verify(sig, msg, pub_hex))
    -- pubkey accepted as raw 32 bytes too
    assert.is_true(ed.verify(sig, msg, ed.from_hex(pub_hex)))
  end)

  it("public_key_of is deterministic and agrees with generate", function()
    local priv, pub_hex = ed.generate_keypair()
    assert.equals(pub_hex, ed.to_hex(ed.public_key_of(priv)))
  end)

  it("tampered message verifies false", function()
    local priv, pub_hex = ed.generate_keypair()
    local sig = ed.sign("hello", priv)
    assert.is_false(ed.verify(sig, "hellO", pub_hex))
  end)

  it("wrong public key verifies false", function()
    local priv = ed.generate_keypair()
    local _, other_pub = ed.generate_keypair()
    local sig = ed.sign("hello", priv)
    assert.is_false(ed.verify(sig, "hello", other_pub))
  end)

  it("signing is deterministic (same key+msg -> same signature)", function()
    local priv = ed.generate_keypair()
    assert.equals(ed.to_hex(ed.sign("x", priv)), ed.to_hex(ed.sign("x", priv)))
  end)
end)

describe("core.ed25519 verify never throws on malformed input", function()
  local priv, pub_hex = ed.generate_keypair()
  local sig = ed.sign("m", priv)

  it("returns false for a short signature", function()
    assert.is_false(ed.verify("tooshort", "m", pub_hex))
  end)

  it("returns false for a non-string signature", function()
    assert.is_false(ed.verify(nil, "m", pub_hex))
  end)

  it("returns false for a malformed public key", function()
    assert.is_false(ed.verify(sig, "m", "not-hex-and-wrong-length"))
  end)

  it("returns false for a non-string message", function()
    assert.is_false(ed.verify(sig, 12345, pub_hex))
  end)
end)

describe("core.ed25519 cross-language vector (ed25519.json == @noble/ed25519)", function()
  local fx = load_ed25519_fixture()
  local priv = ed.from_hex(fx.priv_hex)

  it("derives the pinned public key from the seed", function()
    assert.equals(fx.pub_hex, ed.to_hex(ed.public_key_of(priv)))
  end)

  it("produces the pinned deterministic signature", function()
    assert.equals(fx.sig_hex, ed.to_hex(ed.sign(fx.msg_utf8, priv)))
  end)

  it("verifies the pinned signature against the pinned pubkey", function()
    assert.is_true(ed.verify(ed.from_hex(fx.sig_hex), fx.msg_utf8, ed.from_hex(fx.pub_hex)))
  end)
end)
