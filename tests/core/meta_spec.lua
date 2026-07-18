--- Shape validator for the `.slog.meta` file (Plan 4 §meta).
--- Mirrors log-core's `validateMetaShape` (packages/log-core/src/meta.ts)
--- field-for-field: same check order, same error kinds
--- (not_object / wrong_version / missing_field / invalid_field). No I/O,
--- no crypto verification here — shape only. Never throws.
local meta = require("provenance.core.meta")
local json = require("provenance.core.json")

local function valid_meta()
  return {
    format_version = "1.0",
    session_id = "sess-1",
    session_pubkey = ("ab"):rep(32), -- 64 hex chars
    encrypted_session_privkey = {
      algorithm = "xchacha20-poly1305-hkdf-sha256-v1",
      nonce = "aa",
      ciphertext = "bb",
      salt = "cc",
      info = "provenance-session-privkey-v1",
    },
    checkpoints = json.array({
      { seq = 1, hash = ("11"):rep(32), sig = ("22"):rep(64) },
    }),
  }
end

describe("meta.validate_shape: valid input", function()
  it("accepts a fully-valid SlogMeta", function()
    local res = meta.validate_shape(valid_meta())
    assert.is_true(res.ok)
    assert.equals("1.0", res.value.format_version)
    assert.equals("sess-1", res.value.session_id)
  end)

  it("accepts an empty checkpoints array", function()
    local m = valid_meta()
    m.checkpoints = json.array({})
    local res = meta.validate_shape(m)
    assert.is_true(res.ok)
    assert.equals(0, #res.value.checkpoints)
  end)
end)

describe("meta.validate_shape: top-level shape", function()
  it("rejects a non-table value", function()
    local res_nil = meta.validate_shape(nil)
    assert.is_false(res_nil.ok)
    assert.equals("not_object", res_nil.error.kind)

    for _, v in ipairs({ "x", 5, true }) do
      local res = meta.validate_shape(v)
      assert.is_false(res.ok)
      assert.equals("not_object", res.error.kind)
    end
  end)

  it("rejects an array at the top level", function()
    local res = meta.validate_shape(json.array({ 1, 2, 3 }))
    assert.is_false(res.ok)
    assert.equals("not_object", res.error.kind)
  end)

  it("rejects json.NULL at the top level", function()
    local res = meta.validate_shape(json.NULL)
    assert.is_false(res.ok)
    assert.equals("not_object", res.error.kind)
  end)
end)

describe("meta.validate_shape: format_version", function()
  it("rejects a wrong format_version with actual", function()
    local m = valid_meta()
    m.format_version = "2.0"
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("wrong_version", res.error.kind)
    assert.equals("2.0", res.error.actual)
  end)

  it("rejects a missing format_version (actual = nil)", function()
    local m = valid_meta()
    m.format_version = nil
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("wrong_version", res.error.kind)
    assert.is_nil(res.error.actual)
  end)
end)

describe("meta.validate_shape: session_id", function()
  it("rejects a missing session_id", function()
    local m = valid_meta()
    m.session_id = nil
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
    assert.equals("session_id", res.error.field)
  end)

  it("rejects an empty-string session_id", function()
    local m = valid_meta()
    m.session_id = ""
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("session_id", res.error.field)
  end)

  it("rejects a non-string session_id", function()
    local m = valid_meta()
    m.session_id = 42
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("session_id", res.error.field)
  end)
end)

describe("meta.validate_shape: session_pubkey", function()
  it("rejects a missing session_pubkey", function()
    local m = valid_meta()
    m.session_pubkey = nil
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
    assert.equals("session_pubkey", res.error.field)
  end)

  it("rejects a session_pubkey that is too short", function()
    local m = valid_meta()
    m.session_pubkey = "ab12"
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("session_pubkey", res.error.field)
  end)

  it("rejects uppercase hex in session_pubkey", function()
    local m = valid_meta()
    m.session_pubkey = ("AB"):rep(32)
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("session_pubkey", res.error.field)
  end)
end)

describe("meta.validate_shape: encrypted_session_privkey", function()
  it("rejects a missing encrypted_session_privkey", function()
    local m = valid_meta()
    m.encrypted_session_privkey = nil
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
    assert.equals("encrypted_session_privkey", res.error.field)
  end)

  it("rejects a non-object encrypted_session_privkey", function()
    local m = valid_meta()
    m.encrypted_session_privkey = "not-an-object"
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("encrypted_session_privkey", res.error.field)
  end)

  it("rejects an array encrypted_session_privkey", function()
    local m = valid_meta()
    m.encrypted_session_privkey = json.array({ 1, 2 })
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("encrypted_session_privkey", res.error.field)
  end)

  it("rejects a wrong algorithm", function()
    local m = valid_meta()
    m.encrypted_session_privkey.algorithm = "aes-256-gcm"
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("encrypted_session_privkey.algorithm", res.error.field)
  end)

  it("rejects a missing algorithm", function()
    local m = valid_meta()
    m.encrypted_session_privkey.algorithm = nil
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
    assert.equals("encrypted_session_privkey.algorithm", res.error.field)
  end)

  for _, field in ipairs({ "nonce", "ciphertext", "salt" }) do
    it("rejects a missing " .. field, function()
      local m = valid_meta()
      m.encrypted_session_privkey[field] = nil
      local res = meta.validate_shape(m)
      assert.is_false(res.ok)
      assert.equals("missing_field", res.error.kind)
      assert.equals("encrypted_session_privkey." .. field, res.error.field)
    end)

    it("rejects a non-hex " .. field, function()
      local m = valid_meta()
      m.encrypted_session_privkey[field] = "not-hex!"
      local res = meta.validate_shape(m)
      assert.is_false(res.ok)
      assert.equals("invalid_field", res.error.kind)
      assert.equals("encrypted_session_privkey." .. field, res.error.field)
    end)

    it("rejects an empty-string " .. field, function()
      local m = valid_meta()
      m.encrypted_session_privkey[field] = ""
      local res = meta.validate_shape(m)
      assert.is_false(res.ok)
      assert.equals("invalid_field", res.error.kind)
      assert.equals("encrypted_session_privkey." .. field, res.error.field)
    end)

    it("rejects uppercase hex in " .. field, function()
      local m = valid_meta()
      m.encrypted_session_privkey[field] = "AA"
      local res = meta.validate_shape(m)
      assert.is_false(res.ok)
      assert.equals("invalid_field", res.error.kind)
      assert.equals("encrypted_session_privkey." .. field, res.error.field)
    end)
  end

  it("rejects a missing info", function()
    local m = valid_meta()
    m.encrypted_session_privkey.info = nil
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
    assert.equals("encrypted_session_privkey.info", res.error.field)
  end)

  it("rejects an empty-string info", function()
    local m = valid_meta()
    m.encrypted_session_privkey.info = ""
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("encrypted_session_privkey.info", res.error.field)
  end)
end)

describe("meta.validate_shape: checkpoints", function()
  it("rejects a missing checkpoints field", function()
    local m = valid_meta()
    m.checkpoints = nil
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("missing_field", res.error.kind)
    assert.equals("checkpoints", res.error.field)
  end)

  it("rejects checkpoints that is not an array", function()
    local m = valid_meta()
    m.checkpoints = { seq = 1 }
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("checkpoints", res.error.field)
  end)

  it("rejects a checkpoint with a bad seq (0-indexed field name)", function()
    local m = valid_meta()
    m.checkpoints = json.array({ { seq = "1", hash = ("11"):rep(32), sig = ("22"):rep(64) } })
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("checkpoints[0].seq", res.error.field)
  end)

  it("rejects a checkpoint with a bad hash", function()
    local m = valid_meta()
    m.checkpoints = json.array({ { seq = 1, hash = "short", sig = ("22"):rep(64) } })
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("checkpoints[0].hash", res.error.field)
  end)

  it("rejects a checkpoint with a bad sig", function()
    local m = valid_meta()
    m.checkpoints = json.array({ { seq = 1, hash = ("11"):rep(32), sig = "short" } })
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("checkpoints[0].sig", res.error.field)
  end)

  it("indexes the second checkpoint as checkpoints[1]", function()
    local m = valid_meta()
    m.checkpoints = json.array({
      { seq = 1, hash = ("11"):rep(32), sig = ("22"):rep(64) },
      { seq = 2, hash = ("33"):rep(32), sig = "bad" },
    })
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("checkpoints[1].sig", res.error.field)
  end)

  it("rejects a non-object checkpoint entry", function()
    local m = valid_meta()
    m.checkpoints = json.array({ "not-an-object" })
    local res = meta.validate_shape(m)
    assert.is_false(res.ok)
    assert.equals("invalid_field", res.error.kind)
    assert.equals("checkpoints[0]", res.error.field)
  end)
end)

describe("meta.validate_shape: never throws on garbage input", function()
  it("survives arbitrary weird inputs without raising", function()
    assert.is_true((pcall(meta.validate_shape, nil)))

    local garbage = {
      5, "str", true, {}, json.array({}),
      { format_version = "1.0" },
      { format_version = "1.0", session_id = {} },
      setmetatable({}, { __index = function() error("boom") end }),
    }
    for _, g in ipairs(garbage) do
      local ok = pcall(meta.validate_shape, g)
      assert.is_true(ok)
    end
  end)
end)
