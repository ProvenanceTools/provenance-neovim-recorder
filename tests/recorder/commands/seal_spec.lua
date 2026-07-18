--- seal.seal_bundle (Plan 4) — port of the monorepo's seal.ts `sealBundle`.
--- Real vim.uv against real temp-dir fixtures (CLAUDE.md's "real, focused"
--- bar for editor-seam code), real ed25519 keys, and `/usr/bin/unzip` to
--- prove the produced ZIP is a real, spec-compliant archive — mirrors the
--- bar already set by zip_writer_spec.lua and meta_writer_spec.lua.
---
--- The "real session" fixture below wires session_host + recorder_context
--- exactly as the live recorder would: a fresh per-session ed25519 keypair
--- (core.session_keys), a session.start payload built by
--- recorder.session.recorder_context, and a doc.open event, chained via
--- recorder.session.session_host and persisted to a `.slog` (+ `.slog.meta`
--- via recorder.io.meta_writer) — so seal is exercised against exactly the
--- on-disk shape it will see in production, not a hand-rolled shortcut.
local seal = require("provenance.recorder.commands.seal")
local core_bundle = require("provenance.core.bundle")
local core_sha256 = require("provenance.core.sha256")
local core_ndjson = require("provenance.core.ndjson")
local core_clock = require("provenance.core.clock")
local session_keys = require("provenance.core.session_keys")
local session_host = require("provenance.recorder.session.session_host")
local recorder_context = require("provenance.recorder.session.recorder_context")
local meta_writer = require("provenance.recorder.io.meta_writer")

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

-- Low-level raw write (not atomic — this is test-fixture setup, not code
-- under test). Mirrors the uv fs_open/fs_write/fs_close idiom used by
-- recorder.io.atomic_write and recorder.io.meta_writer.
local function write_raw_file(path, contents)
  local uv = vim.uv or vim.loop
  local fd = assert(uv.fs_open(path, "w", 420)) -- 420 = 0o644
  uv.fs_write(fd, contents)
  uv.fs_close(fd)
end

local function unzip_available()
  return vim.fn.executable("unzip") == 1
end

--- Build a real session on disk inside `provenance_dir`: a fresh ed25519
--- keypair, a chained session.start + doc.open pair emitted through a real
--- SessionHost, persisted as `session-<id>.slog` (NDJSON, one
--- json.canonicalize'd HashedEnvelope per line) and `session-<id>.slog.meta`
--- (via meta_writer, with the session privkey encrypted under a stand-in
--- manifest signature — the same convention meta_writer_spec.lua uses).
--- @return table { kp, session_id, slog_path, meta_path, slog_name, meta_name, entries }
local function build_session_fixture(provenance_dir)
  local kp = session_keys.generate()
  local manifest_sig_hex = ("ab"):rep(64)
  local clock = core_clock.fixed(0, 0)

  local entries = {}
  local host = session_host.new({
    session_id = "unused-host-id", -- distinct from data.session_id below; seal only reads entries[1].data
    clock = clock,
    on_entry = function(e)
      entries[#entries + 1] = e
    end,
  })

  local start_data = recorder_context.build_recorder_context({
    manifest = { assignment_id = "hw3", semester = "fa25", sig = manifest_sig_hex },
    session_pubkey_hex = kp.public_key_hex,
    env = { uuid = function() return "sess-fixture-1" end },
  })

  host.emit("session.start", start_data)
  host.emit("doc.open", { path = "src/main.py" })

  local session_id = start_data.session_id
  local slog_name = "session-" .. session_id .. ".slog"
  local meta_name = slog_name .. ".meta"
  local slog_path = provenance_dir .. "/" .. slog_name
  local meta_path = provenance_dir .. "/" .. meta_name

  local lines = {}
  for _, e in ipairs(entries) do
    lines[#lines + 1] = core_ndjson.serialize_entry(e)
  end
  write_raw_file(slog_path, table.concat(lines))

  local enc = session_keys.encrypt_privkey(kp.private_key, manifest_sig_hex)
  meta_writer.create({
    meta_path = meta_path,
    session_id = session_id,
    session_pubkey_hex = kp.public_key_hex,
    encrypted_privkey = enc,
  })

  return {
    kp = kp,
    session_id = session_id,
    slog_path = slog_path,
    meta_path = meta_path,
    slog_name = slog_name,
    meta_name = meta_name,
    entries = entries,
  }
end

describe("seal.seal_bundle", function()
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

  it("returns no_sessions when provenance_dir doesn't exist", function()
    local root = new_tempdir()
    local workspace = root .. "/workspace"
    vim.fn.mkdir(workspace, "p")

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = workspace .. "/.provenance",
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = {},
      session_privkey = ("\0"):rep(32),
      session_pubkey_hex = ("00"):rep(32),
      now = function() return "2026-05-19T14:30:00.000Z" end,
    })

    assert.same({ kind = "no_sessions" }, result)
  end)

  it("returns no_sessions when provenance_dir exists but has no .slog files", function()
    local root = new_tempdir()
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    -- A stray non-.slog file must not count.
    write_raw_file(provenance_dir .. "/notes.txt", "hello")

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = {},
      session_privkey = ("\0"):rep(32),
      session_pubkey_hex = ("00"):rep(32),
      now = function() return "2026-05-19T14:30:00.000Z" end,
    })

    assert.same({ kind = "no_sessions" }, result)
  end)

  it("happy path: seals a verifiable, signed bundle and a valid zip", function()
    if not unzip_available() then
      pending("unzip not available on this machine")
      return
    end

    local root = new_tempdir()
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    vim.fn.mkdir(workspace .. "/src", "p")

    local fixture = build_session_fixture(provenance_dir)
    write_raw_file(workspace .. "/src/main.py", "print('hello')\n")

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = { "src/main.py" },
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      now = function() return "2026-05-19T14:30:00.000Z" end,
    })

    assert.equals("ok", result.kind)
    assert.is_false(result.warnings.chain_broken)
    assert.is_false(result.warnings.unreadable_session)

    -- The manifest verifies against the session pubkey.
    local manifest_json_text = read_all(provenance_dir .. "/manifest.json")
    local sig_text = read_all(provenance_dir .. "/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_json_text, sig_text, fixture.kp.public_key_hex))
    assert.equals(core_sha256.hex(manifest_json_text), result.manifest_sha256)

    -- Filename: colons in `now()` become dashes.
    local expected_bundle_path = workspace .. "/hw3-bundle-2026-05-19T14-30-00.000Z.zip"
    assert.equals(expected_bundle_path, result.bundle_path)
    assert.is_true(vim.uv.fs_stat(result.bundle_path) ~= nil)

    local test_out = vim.fn.system({ "unzip", "-t", result.bundle_path })
    assert.equals(0, vim.v.shell_error, test_out)
    assert.is_truthy(test_out:find("No errors detected"))

    local list_out = vim.fn.system({ "unzip", "-l", result.bundle_path })
    assert.equals(0, vim.v.shell_error)
    assert.is_truthy(list_out:find("manifest.json", 1, true))
    assert.is_truthy(list_out:find("manifest.sig", 1, true))
    assert.is_truthy(list_out:find(fixture.slog_name, 1, true))
    assert.is_truthy(list_out:find(fixture.meta_name, 1, true))
    assert.is_truthy(list_out:find("src/main.py", 1, true))
  end)

  it("marks a missing reviewed file as status=missing and excludes it from the zip", function()
    if not unzip_available() then
      pending("unzip not available on this machine")
      return
    end

    local root = new_tempdir()
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    -- Deliberately do NOT create src/main.py.

    local fixture = build_session_fixture(provenance_dir)

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = { "src/main.py" },
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      now = function() return "2026-05-19T14:30:00.000Z" end,
    })

    assert.equals("ok", result.kind)

    local manifest_json_text = read_all(provenance_dir .. "/manifest.json")
    local decoded = vim.json.decode(manifest_json_text)
    local found
    for _, f in ipairs(decoded.submission_files) do
      if f.path == "src/main.py" then
        found = f
      end
    end
    assert.is_not_nil(found)
    assert.equals("missing", found.status)
    assert.is_true(found.sha256 == vim.NIL or found.sha256 == nil)

    local list_out = vim.fn.system({ "unzip", "-l", result.bundle_path })
    assert.equals(0, vim.v.shell_error)
    assert.is_falsy(list_out:find("src/main.py", 1, true))
  end)

  it("still seals (with chain_broken=true) when a slog's hash chain is corrupted", function()
    local root = new_tempdir()
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    local fixture = build_session_fixture(provenance_dir)
    assert.is_true(#fixture.entries >= 2)

    -- Corrupt the second entry's hash so the chain no longer validates,
    -- and rewrite the .slog with the corrupted line.
    fixture.entries[2].hash = ("00"):rep(32)
    local lines = {}
    for _, e in ipairs(fixture.entries) do
      lines[#lines + 1] = core_ndjson.serialize_entry(e)
    end
    write_raw_file(fixture.slog_path, table.concat(lines))

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = {},
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      now = function() return "2026-05-19T14:30:00.000Z" end,
    })

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.chain_broken)
    assert.is_false(result.warnings.unreadable_session)
    assert.is_true(vim.uv.fs_stat(result.bundle_path) ~= nil)
  end)
end)
