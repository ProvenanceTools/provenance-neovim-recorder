--- Signed seq->hash checkpoints.
--- sign() builds {hash, seq} (JCS sorts keys, so "hash" precedes "seq"),
--- canonicalizes it, and ed25519-signs; verify() rebuilds the same payload
--- and never throws, returning false on any malformed input.
local checkpoint = require("provenance.core.checkpoint")
local ed25519 = require("provenance.core.ed25519")

describe("checkpoint.sign / checkpoint.verify round-trip", function()
  it("signs and verifies with a freshly generated keypair", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local entry_hash = ("ab"):rep(32)
    local cp = checkpoint.sign(42, entry_hash, priv)

    assert.equals(42, cp.seq)
    assert.equals(entry_hash, cp.hash)
    assert.equals(128, #cp.sig)
    assert.matches("^[0-9a-f]+$", cp.sig)

    assert.is_true(checkpoint.verify(cp, pub_hex))
  end)

  it("fails verification against the wrong public key", function()
    local priv, _ = ed25519.generate_keypair()
    local _, other_pub_hex = ed25519.generate_keypair()
    local cp = checkpoint.sign(1, ("cd"):rep(32), priv)

    assert.is_false(checkpoint.verify(cp, other_pub_hex))
  end)

  it("fails verification if the hash is tampered", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local cp = checkpoint.sign(7, ("11"):rep(32), priv)
    cp.hash = ("22"):rep(32)

    assert.is_false(checkpoint.verify(cp, pub_hex))
  end)

  it("fails verification if the seq is tampered", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local cp = checkpoint.sign(7, ("11"):rep(32), priv)
    cp.seq = 8

    assert.is_false(checkpoint.verify(cp, pub_hex))
  end)
end)

describe("checkpoint.verify malformed input (never throws)", function()
  local priv, pub_hex = ed25519.generate_keypair()
  local good = checkpoint.sign(1, ("ab"):rep(32), priv)

  it("rejects a non-table checkpoint", function()
    assert.is_false(checkpoint.verify(nil, pub_hex))
    assert.is_false(checkpoint.verify("not a table", pub_hex))
    assert.is_false(checkpoint.verify(5, pub_hex))
  end)

  it("rejects a missing/non-number seq", function()
    local cp = vim.deepcopy(good)
    cp.seq = nil
    assert.is_false(checkpoint.verify(cp, pub_hex))

    cp = vim.deepcopy(good)
    cp.seq = "1"
    assert.is_false(checkpoint.verify(cp, pub_hex))
  end)

  it("rejects a missing/empty hash", function()
    local cp = vim.deepcopy(good)
    cp.hash = nil
    assert.is_false(checkpoint.verify(cp, pub_hex))

    cp = vim.deepcopy(good)
    cp.hash = ""
    assert.is_false(checkpoint.verify(cp, pub_hex))
  end)

  it("rejects a malformed sig (wrong length / not hex)", function()
    local cp = vim.deepcopy(good)
    cp.sig = "not-hex"
    assert.is_false(checkpoint.verify(cp, pub_hex))

    cp = vim.deepcopy(good)
    cp.sig = cp.sig:sub(1, -3) -- too short
    assert.is_false(checkpoint.verify(cp, pub_hex))

    cp = vim.deepcopy(good)
    cp.sig = nil
    assert.is_false(checkpoint.verify(cp, pub_hex))
  end)

  it("rejects a malformed pubkey_hex gracefully", function()
    assert.is_false(checkpoint.verify(good, "not-a-pubkey"))
    assert.is_false(checkpoint.verify(good, nil))
  end)
end)
