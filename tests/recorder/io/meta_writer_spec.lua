--- Writer for `.slog.meta` (Plan 4). Real vim.uv against real temp-dir
--- fixtures, per CLAUDE.md's "real, focused" bar for editor-seam code.
--- Verifies: immediate persistence on create(), on-disk bytes pinned to
--- `json.canonicalize(meta)` exactly, empty checkpoints serialize as `[]`
--- (not `{}`), ordered checkpoint appends, round-trip validation via
--- `core.meta.validate_shape`, and no `.tmp` leftovers.
local meta_writer = require("provenance.recorder.io.meta_writer")
local json = require("provenance.core.json")
local meta = require("provenance.core.meta")
local session_keys = require("provenance.core.session_keys")
local checkpoint = require("provenance.core.checkpoint")

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

-- Real round-trip encrypted_session_privkey via core.session_keys, keyed by
-- a stand-in manifest signature (128-hex, as a real activation-gate sig
-- would be).
local function make_encrypted_privkey()
  local kp = session_keys.generate()
  local manifest_sig_hex = ("ab"):rep(64)
  return session_keys.encrypt_privkey(kp.private_key, manifest_sig_hex), kp
end

describe("meta_writer.create", function()
  local tempdirs = {}

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function new_tempdir()
    local dir = make_tempdir()
    table.insert(tempdirs, dir)
    return dir
  end

  it("writes the meta file immediately and it validates via core.meta", function()
    local dir = new_tempdir()
    local meta_path = dir .. "/session.slog.meta"
    local enc = make_encrypted_privkey()

    meta_writer.create({
      meta_path = meta_path,
      session_id = "sess-abc",
      session_pubkey_hex = ("cd"):rep(32),
      encrypted_privkey = enc,
    })

    assert.is_true(vim.uv.fs_stat(meta_path) ~= nil)

    local text = read_all(meta_path)
    local decoded = vim.json.decode(text)
    local res = meta.validate_shape(decoded)
    assert.is_true(res.ok)
    assert.equals("sess-abc", res.value.session_id)
    assert.equals(("cd"):rep(32), res.value.session_pubkey)
    assert.equals(0, #res.value.checkpoints)
  end)

  it("on-disk bytes exactly equal json.canonicalize(meta)", function()
    local dir = new_tempdir()
    local meta_path = dir .. "/session.slog.meta"
    local enc = make_encrypted_privkey()

    local mw = meta_writer.create({
      meta_path = meta_path,
      session_id = "sess-xyz",
      session_pubkey_hex = ("11"):rep(32),
      encrypted_privkey = enc,
    })

    local expected = json.canonicalize(mw.get_meta())
    local actual = read_all(meta_path)
    assert.equals(expected, actual)
  end)

  it("serializes an empty checkpoints array as [] not {}", function()
    local dir = new_tempdir()
    local meta_path = dir .. "/session.slog.meta"
    local enc = make_encrypted_privkey()

    meta_writer.create({
      meta_path = meta_path,
      session_id = "sess-empty",
      session_pubkey_hex = ("22"):rep(32),
      encrypted_privkey = enc,
    })

    local text = read_all(meta_path)
    assert.is_not_nil(text:find('"checkpoints":[]', 1, true))
  end)

  it("leaves no .tmp sibling after create()", function()
    local dir = new_tempdir()
    local meta_path = dir .. "/session.slog.meta"
    local enc = make_encrypted_privkey()

    meta_writer.create({
      meta_path = meta_path,
      session_id = "sess-tmp",
      session_pubkey_hex = ("33"):rep(32),
      encrypted_privkey = enc,
    })

    local leftovers = vim.fn.glob(dir .. "/*.tmp", true, true)
    assert.same({}, leftovers)
  end)
end)

describe("meta_writer.append_checkpoint", function()
  local tempdirs = {}

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function new_tempdir()
    local dir = make_tempdir()
    table.insert(tempdirs, dir)
    return dir
  end

  it("appends checkpoints in order, rewrites atomically, and stays valid", function()
    local dir = new_tempdir()
    local meta_path = dir .. "/session.slog.meta"
    local enc, kp = make_encrypted_privkey()

    local mw = meta_writer.create({
      meta_path = meta_path,
      session_id = "sess-cp",
      session_pubkey_hex = kp.public_key_hex,
      encrypted_privkey = enc,
    })

    local cp1 = checkpoint.sign(100, ("aa"):rep(32), kp.private_key)
    local cp2 = checkpoint.sign(200, ("bb"):rep(32), kp.private_key)

    mw.append_checkpoint(cp1)
    mw.append_checkpoint(cp2)

    local text = read_all(meta_path)
    local decoded = vim.json.decode(text)
    local res = meta.validate_shape(decoded)
    assert.is_true(res.ok)

    assert.equals(2, #res.value.checkpoints)
    assert.equals(100, res.value.checkpoints[1].seq)
    assert.equals(200, res.value.checkpoints[2].seq)

    -- Sanity: signatures verify against the session pubkey.
    assert.is_true(checkpoint.verify(res.value.checkpoints[1], kp.public_key_hex))
    assert.is_true(checkpoint.verify(res.value.checkpoints[2], kp.public_key_hex))

    -- On-disk bytes still pinned to the (now-mutated) in-memory meta.
    assert.equals(json.canonicalize(mw.get_meta()), text)

    local leftovers = vim.fn.glob(dir .. "/*.tmp", true, true)
    assert.same({}, leftovers)
  end)

  it("keeps checkpoints tagged as a json.array after pushes (serializes as an array)", function()
    local dir = new_tempdir()
    local meta_path = dir .. "/session.slog.meta"
    local enc, kp = make_encrypted_privkey()

    local mw = meta_writer.create({
      meta_path = meta_path,
      session_id = "sess-tag",
      session_pubkey_hex = kp.public_key_hex,
      encrypted_privkey = enc,
    })

    mw.append_checkpoint(checkpoint.sign(1, ("cc"):rep(32), kp.private_key))

    assert.is_true(json.is_array(mw.get_meta().checkpoints))
    local text = read_all(meta_path)
    assert.is_not_nil(text:find('"checkpoints":[{', 1, true))
  end)
end)

describe("meta_writer.dispose", function()
  it("is a no-op teardown that does not error", function()
    local dir = make_tempdir()
    local meta_path = dir .. "/session.slog.meta"
    local enc = make_encrypted_privkey()

    local mw = meta_writer.create({
      meta_path = meta_path,
      session_id = "sess-dispose",
      session_pubkey_hex = ("44"):rep(32),
      encrypted_privkey = enc,
    })

    assert.has_no.errors(function() mw.dispose() end)
    assert.has_no.errors(function() mw.dispose() end) -- idempotent

    vim.fn.delete(dir, "rf")
  end)
end)
