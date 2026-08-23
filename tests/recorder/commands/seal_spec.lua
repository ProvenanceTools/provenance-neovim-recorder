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

--- This spec file's own repo root, resolved from `debug.getinfo` (same
--- technique as `tests/recorder/io/workspace_file_read_spec.lua`) rather
--- than `getcwd()`, so it does not depend on the Makefile's invocation
--- directory. Walks up from `tests/recorder/commands/seal_spec.lua` to the
--- repo root: strip the filename, then `commands` -> `recorder` -> `tests`
--- -> root.
local function resolve_repo_root()
  local info = debug.getinfo(1, "S")
  local source = info.source
  assert(type(source) == "string" and source:sub(1, 1) == "@", "could not resolve spec file source path")
  local dir = source:sub(2)
  for _ = 1, 4 do
    dir = dir:match("^(.*)/[^/]+$")
    assert(dir ~= nil, "could not walk up to repo root from spec file path")
  end
  return dir
end

local REPO_ROOT = resolve_repo_root()

--- Build a real session on disk inside `provenance_dir`: a fresh ed25519
--- keypair, a chained session.start + doc.open pair emitted through a real
--- SessionHost, persisted as `session-<id>.slog` (NDJSON, one
--- json.canonicalize'd HashedEnvelope per line) and `session-<id>.slog.meta`
--- (via meta_writer, with the session privkey encrypted under a stand-in
--- manifest signature — the same convention meta_writer_spec.lua uses).
---
--- `opts.logical_id` overrides the injected logical session id (the one that
--- lands in session.start.data.session_id and that a rolling seal is named
--- after); `opts.file_uuid` overrides the `.slog` FILENAME uuid independently,
--- so a test can hold the two-uuid rule apart instead of letting the default
--- collapse them onto one string.
--- @return table { kp, session_id, slog_path, meta_path, slog_name, meta_name, entries }
local function build_session_fixture(provenance_dir, opts)
  opts = opts or {}
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
    env = { uuid = function() return opts.logical_id or "sess-fixture-1" end },
  })

  host.emit("session.start", start_data)
  host.emit("doc.open", { path = "src/main.py" })

  local session_id = start_data.session_id
  local slog_name = "session-" .. (opts.file_uuid or session_id) .. ".slog"
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

--- ORPHAN / CONTENTLESS SESSION GUARD.
---
--- `analysis-core`'s loader pairs `session-<uuid>.slog` with its `.slog.meta` by
--- filename and rejects THE WHOLE BUNDLE if either half is missing, before a
--- single validation check runs. So one unpaired file used to cost a student
--- every session they recorded. Seal must drop the unusable file, warn, and
--- still produce something submittable — never abort.
describe("seal.seal_bundle orphan guard", function()
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

  local function seal_in(provenance_dir, workspace, fixture)
    return seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = {},
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      compute_extension_hash = function() return ("cd"):rep(32) end,
      now = function() return "2026-05-19T14:30:00.000Z" end,
    })
  end

  local function setup()
    local root = new_tempdir()
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    return workspace, provenance_dir, build_session_fixture(provenance_dir)
  end

  local function zip_names(bundle_path)
    local names = {}
    for _, line in ipairs(vim.fn.systemlist({ "unzip", "-Z1", bundle_path })) do
      names[#names + 1] = line
    end
    return names
  end

  local function contains(list, want)
    for _, v in ipairs(list) do
      if v == want then return true end
    end
    return false
  end

  it("drops an orphaned .slog.meta and reports it, keeping the good session", function()
    local workspace, provenance_dir, fx = setup()
    -- A second session that left only a meta behind — exactly what
    -- chain_recovery's quarantine produces when it renames the .slog away.
    local orphan_meta = provenance_dir .. "/session-orphan-1111.slog.meta"
    write_raw_file(orphan_meta, '{"format_version":"1.0","session_id":"orphan-1111"}')

    local result = seal_in(provenance_dir, workspace, fx)

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.orphaned_meta, "the drop must be reported, never silent")

    if unzip_available() then
      local names = zip_names(result.bundle_path)
      assert.is_false(contains(names, "session-orphan-1111.slog.meta"), "orphan must not be packed")
      assert.is_true(contains(names, fx.slog_name), "the good session must survive")
      assert.is_true(contains(names, fx.meta_name))
    end
  end)

  it("drops a CONTENTLESS session (started, never flushed) and reports it", function()
    -- session_writer.open() now creates the .slog eagerly, so a session that
    -- starts and never flushes leaves a well-PAIRED but empty pair. The loader
    -- rejects that too (first_event_not_session_start, actualKind "none"), so
    -- the guard has to cover it as well as the orphan case.
    local workspace, provenance_dir, fx = setup()
    write_raw_file(provenance_dir .. "/session-empty-2222.slog", "")
    write_raw_file(provenance_dir .. "/session-empty-2222.slog.meta", '{"session_id":"empty-2222"}')

    local result = seal_in(provenance_dir, workspace, fx)

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.empty_session)

    if unzip_available() then
      local names = zip_names(result.bundle_path)
      assert.is_false(contains(names, "session-empty-2222.slog"))
      assert.is_false(contains(names, "session-empty-2222.slog.meta"))
      assert.is_true(contains(names, fx.slog_name))
    end
  end)

  it("drops an orphaned .slog from the MANIFEST as well as the zip", function()
    -- The two must agree: a manifest naming a session whose file is absent is
    -- just another way to make the bundle unopenable.
    local workspace, provenance_dir, fx = setup()
    write_raw_file(provenance_dir .. "/session-lonely-3333.slog", '{"seq":0}\n')

    local result = seal_in(provenance_dir, workspace, fx)

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.orphaned_slog)

    local manifest = vim.json.decode(read_all(provenance_dir .. "/manifest.json"))
    for _, s in ipairs(manifest.sessions) do
      assert.is_not.equals("session-lonely-3333.slog", s.slog_filename or s.filename)
    end
    assert.equals(1, #manifest.sessions, "only the paired, non-empty session is in the manifest")

    if unzip_available() then
      assert.is_false(contains(zip_names(result.bundle_path), "session-lonely-3333.slog"))
    end
  end)

  it("a clean provenance dir sets no orphan warnings", function()
    local workspace, provenance_dir, fx = setup()
    local result = seal_in(provenance_dir, workspace, fx)
    assert.equals("ok", result.kind)
    assert.is_false(result.warnings.orphaned_meta)
    assert.is_false(result.warnings.orphaned_slog)
    assert.is_false(result.warnings.empty_session)
  end)

  it("NEVER aborts: an orphan alone still seals, reporting no_sessions only when nothing is usable", function()
    local root = new_tempdir()
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    write_raw_file(provenance_dir .. "/session-orphan-9999.slog.meta", "{}")

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

    -- Not an error, not a crash: the existing "nothing to seal" result.
    assert.equals("no_sessions", result.kind)
  end)
end)

--- ROLLING-SEAL ORPHAN GUARD.
---
--- The rolling seal (`manifest-<session_id>.json` + `.sig`) is a THIRD
--- per-session artifact beside the `.slog` and `.slog.meta`, written eagerly at
--- session start — before the `.slog` has been flushed even once — and rewritten
--- at every checkpoint and at teardown. It therefore survives every reason the
--- guard above has for dropping a session, and used to be packed regardless.
---
--- `analysis-core`'s `reconcileRollingSealsWithSessions` reports `no_session_log`
--- for a seal whose session is not in the bundle: the seal names a recording
--- that is not here, so its signature can never be checked (the verifying pubkey
--- lives in that session's own session.start). That defect fails check 1
--- (`manifest_sig`) for THE WHOLE BUNDLE — the same blast radius as
--- `orphaned_meta`, and the same rule applies: drop it from the zip, warn, never
--- abort, and never touch what is on disk.
describe("seal.seal_bundle rolling-seal orphan guard", function()
  local rolling_seal_writer = require("provenance.recorder.io.rolling_seal_writer")

  -- Hex ids on purpose. `rolling_manifest.parse_filename` only accepts
  -- `[0-9a-f-]`, so an id like "sess-fixture-1" would never be recognised as a
  -- rolling manifest and every assertion below would pass vacuously.
  local PACKED_ID = "aaaaaaaa-1111-4111-8111-111111111111"
  local PACKED_FILE_UUID = "cccccccc-3333-4333-8333-333333333333"
  local DROPPED_ID = "bbbbbbbb-2222-4222-8222-222222222222"

  local tempdirs = {}

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function setup()
    local root = make_tempdir()
    table.insert(tempdirs, root)
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    -- Logical id and filename uuid deliberately DIFFERENT (two-uuid rule): a
    -- guard that keyed off the `.slog` filename would drop every rolling seal a
    -- real recorder writes, and a fixture that collapsed the two would hide it.
    local fx = build_session_fixture(provenance_dir, {
      logical_id = PACKED_ID,
      file_uuid = PACKED_FILE_UUID,
    })
    return workspace, provenance_dir, fx
  end

  --- Write a real rolling seal through the production writer, so the filenames
  --- under test are the ones the recorder actually emits rather than hand-spelled.
  local function roll(provenance_dir, workspace, fx, session_id, slog_path)
    local res = rolling_seal_writer.write_rolling_seal({
      provenance_dir = provenance_dir,
      session_id = session_id,
      prev_session_id = nil,
      slog_path = slog_path,
      workspace = workspace,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = {},
      session_privkey = fx.kp.private_key,
      extension_hash = ("cd"):rep(32),
    })
    assert.equals("written", res.kind)
  end

  local function seal_in(provenance_dir, workspace, fixture)
    return seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = {},
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      compute_extension_hash = function() return ("cd"):rep(32) end,
      now = function() return "2026-05-19T14:30:00.000Z" end,
    })
  end

  local function packed_names(bundle_path)
    local names = {}
    for _, line in ipairs(vim.fn.systemlist({ "unzip", "-Z1", bundle_path })) do
      names[line] = true
    end
    return names
  end

  it("drops a rolling seal whose session's log is not in the bundle", function()
    local workspace, provenance_dir, fx = setup()

    -- A second session that started, took its session-start roll, and was torn
    -- down before it ever flushed: a well-paired but ZERO-BYTE `.slog` that the
    -- guard above drops as `empty_session`, and a rolling seal that outlives it.
    -- This is exactly what `scripts/e2e/run_e2e.sh` produces.
    local dropped_slog = provenance_dir .. "/session-" .. DROPPED_ID .. ".slog"
    write_raw_file(dropped_slog, "")
    write_raw_file(dropped_slog .. ".meta", '{"session_id":"' .. DROPPED_ID .. '"}')
    roll(provenance_dir, workspace, fx, DROPPED_ID, dropped_slog)

    local result = seal_in(provenance_dir, workspace, fx)

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.empty_session)
    assert.is_true(result.warnings.orphaned_rolling_seal, "the drop must be reported, never silent")

    if unzip_available() then
      local names = packed_names(result.bundle_path)
      assert.is_nil(names["manifest-" .. DROPPED_ID .. ".json"])
      assert.is_nil(names["manifest-" .. DROPPED_ID .. ".sig"], "the .sig goes with its .json")
    end

    -- Dropped from the ZIP only. The on-disk seal is what a git-submitted
    -- `.provenance/` is read from, and in a shared repo it may be a partner's —
    -- never destroy or rename someone's evidence to make a bundle load.
    assert.is_true(vim.uv.fs_stat(provenance_dir .. "/manifest-" .. DROPPED_ID .. ".json") ~= nil)
    assert.is_true(vim.uv.fs_stat(provenance_dir .. "/manifest-" .. DROPPED_ID .. ".sig") ~= nil)
  end)

  it("keeps the rolling seal of a session that IS packed, matching on the LOGICAL id", function()
    local workspace, provenance_dir, fx = setup()
    roll(provenance_dir, workspace, fx, PACKED_ID, fx.slog_path)
    -- A seal named after the `.slog` FILENAME uuid is an orphan, not a match:
    -- no session.start anywhere claims that id.
    roll(provenance_dir, workspace, fx, PACKED_FILE_UUID, fx.slog_path)

    local result = seal_in(provenance_dir, workspace, fx)
    assert.equals("ok", result.kind)

    if unzip_available() then
      local names = packed_names(result.bundle_path)
      assert.is_true(names["manifest-" .. PACKED_ID .. ".json"] == true, "a live session must keep its seal")
      assert.is_true(names["manifest-" .. PACKED_ID .. ".sig"] == true)
      assert.is_nil(names["manifest-" .. PACKED_FILE_UUID .. ".json"], "two-uuid rule: the filename uuid is not a session id")
      -- The CLASSIC seal is not a rolling seal and is never subject to this guard.
      assert.is_true(names["manifest.json"] == true)
      assert.is_true(names["manifest.sig"] == true)
      assert.is_true(names[fx.slog_name] == true)
      assert.is_true(names[fx.meta_name] == true)
    end
  end)

  it("a dir whose only rolling seal matches its session sets no rolling warning", function()
    local workspace, provenance_dir, fx = setup()
    roll(provenance_dir, workspace, fx, PACKED_ID, fx.slog_path)

    local result = seal_in(provenance_dir, workspace, fx)
    assert.equals("ok", result.kind)
    assert.is_false(result.warnings.orphaned_rolling_seal)
    assert.is_false(result.warnings.empty_session)
    assert.is_false(result.warnings.orphaned_meta)
    assert.is_false(result.warnings.orphaned_slog)
  end)

  it("NEVER aborts: a dir of nothing but orphaned rolling seals still seals the good session", function()
    local workspace, provenance_dir, fx = setup()
    for i = 1, 3 do
      local ghost = string.format("dddddddd-444%d-444%d-844%d-44444444444%d", i, i, i, i)
      roll(provenance_dir, workspace, fx, ghost, provenance_dir .. "/nonexistent.slog")
    end

    local result = seal_in(provenance_dir, workspace, fx)
    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.orphaned_rolling_seal)
    assert.is_true(vim.uv.fs_stat(result.bundle_path) ~= nil)
  end)
end)

--- NEVER report an unreadable reviewed file as missing.
---
--- `read_file_bytes` used to collapse every read failure -- a directory, a
--- permission error, a FIFO, any other errno -- to a bare nil, and the step 3
--- call site turned every one of those into `status = "missing"`: an
--- AFFIRMATIVE claim about a student ("this file was named and is not
--- there") rendered into academic-integrity proceedings. Only ENOENT
--- actually means that. This block proves the fix: a directory, a
--- permission error, and a FIFO are all DROPPED (never "missing", never
--- silently, always via `warnings.unreadable_in_scope_file`), a genuinely
--- absent file still IS "missing", and an ordinary in-workspace symlink to a
--- real file still reads present -- the case a careless `fs_lstat` swap
--- would have broken.
describe("seal.seal_bundle never reports an unreadable file as missing", function()
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

  local function setup()
    local root = new_tempdir()
    local workspace = root .. "/workspace"
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    return workspace, provenance_dir, build_session_fixture(provenance_dir)
  end

  local function submission_files_of(provenance_dir)
    local decoded = vim.json.decode(read_all(provenance_dir .. "/manifest.json"))
    local by_path = {}
    for _, f in ipairs(decoded.submission_files) do
      by_path[f.path] = f
    end
    return decoded.submission_files, by_path
  end

  it("drops a files_under_review entry naming a DIRECTORY, never missing", function()
    -- files_under_review: ["src"] instead of "src/". fs_open SUCCEEDS on a
    -- directory on macOS, so this is a real trap, not a hypothetical.
    local workspace, provenance_dir, fixture = setup()
    vim.fn.mkdir(workspace .. "/src", "p")

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = { "src" },
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      now = function() return "2026-05-19T14:30:10.000Z" end,
    })

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.unreadable_in_scope_file)

    local files, by_path = submission_files_of(provenance_dir)
    assert.equals(0, #files, "a directory entry must be dropped, not recorded at all")
    assert.is_nil(by_path["src"])
  end)

  it("drops a chmod-000 reviewed file, never missing, and sets unreadable_in_scope_file", function()
    local workspace, provenance_dir, fixture = setup()
    local secret = workspace .. "/secret.txt"
    write_raw_file(secret, "top secret")
    local uv = vim.uv or vim.loop
    uv.fs_chmod(secret, tonumber("000", 8))

    -- Verify the denial actually took effect before asserting; a uid that
    -- defeats permission bits (root) makes this pending rather than false.
    local fd = uv.fs_open(secret, "r", 438)
    if fd ~= nil then
      uv.fs_close(fd)
      uv.fs_chmod(secret, tonumber("644", 8))
      pending("running with elevated privileges that defeat permission bits")
      return
    end

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = { "secret.txt" },
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      now = function() return "2026-05-19T14:30:11.000Z" end,
    })
    uv.fs_chmod(secret, tonumber("644", 8))

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.unreadable_in_scope_file)

    local files, by_path = submission_files_of(provenance_dir)
    assert.equals(0, #files)
    assert.is_nil(by_path["secret.txt"])
  end)

  it("still marks a genuinely absent reviewed file as missing, distinct from an unreadable one", function()
    -- The regression a careless fix causes: this legitimate case must survive
    -- untouched even when an unreadable entry is present in the same call.
    local workspace, provenance_dir, fixture = setup()
    vim.fn.mkdir(workspace .. "/src", "p") -- unreadable: a directory

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = { "src", "NotThere.java" },
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      now = function() return "2026-05-19T14:30:12.000Z" end,
    })

    assert.equals("ok", result.kind)
    assert.is_true(result.warnings.unreadable_in_scope_file)

    local files, by_path = submission_files_of(provenance_dir)
    assert.equals(1, #files, "only the genuinely absent file is recorded")
    assert.is_not_nil(by_path["NotThere.java"])
    assert.equals("missing", by_path["NotThere.java"].status)
    assert.is_true(by_path["NotThere.java"].sha256 == vim.NIL or by_path["NotThere.java"].sha256 == nil)
    assert.is_nil(by_path["src"])
  end)

  it("follows an ordinary in-workspace symlink to a real file, and reports it present", function()
    -- The case a careless fs_lstat swap would break: an in-workspace symlink
    -- is a file the student really did submit.
    local workspace, provenance_dir, fixture = setup()
    vim.fn.mkdir(workspace .. "/real", "p")
    write_raw_file(workspace .. "/real/Main.java", "class Main {}")

    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(workspace .. "/real/Main.java", workspace .. "/link.java"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local result = seal.seal_bundle({
      workspace = workspace,
      provenance_dir = provenance_dir,
      assignment_id = "hw3",
      semester = "fa25",
      files_under_review = { "link.java" },
      session_privkey = fixture.kp.private_key,
      session_pubkey_hex = fixture.kp.public_key_hex,
      now = function() return "2026-05-19T14:30:13.000Z" end,
    })

    assert.equals("ok", result.kind)
    assert.is_false(result.warnings.unreadable_in_scope_file)

    local files, by_path = submission_files_of(provenance_dir)
    assert.equals(1, #files)
    assert.equals("present", by_path["link.java"].status)
    assert.equals(core_sha256.hex("class Main {}"), by_path["link.java"].sha256)
  end)

  it("does not hang on a FIFO tracked file, and drops it without emitting missing", function()
    -- Reading a FIFO with no writer BLOCKS THE ENTIRE NEOVIM PROCESS FOREVER
    -- (verified empirically, not theoretical), with no timeout anywhere in
    -- this call stack -- so the risky call must run in a CHILD `nvim -l`
    -- process under a wall-clock jobwait timeout, or a regression wedges the
    -- whole test run instead of failing one test. Same technique as
    -- tests/recorder/io/workspace_file_read_spec.lua's FIFO test.
    if vim.fn.executable("mkfifo") == 0 then
      pending("mkfifo not available on this machine")
      return
    end

    local workspace, provenance_dir, fixture = setup()
    local fifo = workspace .. "/pipe.txt"
    vim.fn.system({ "mkfifo", fifo })
    if vim.v.shell_error ~= 0 then
      pending("mkfifo failed on this machine")
      return
    end

    local out_file = workspace .. "/result.txt"
    local child_script = workspace .. "/child.lua"
    local script = string.format(
      [[
package.path = %q .. "/lua/?.lua;" .. %q .. "/lua/?/init.lua;" .. package.path
local s = require("provenance.recorder.commands.seal")
local res = s.seal_bundle({
  workspace = %q,
  provenance_dir = %q,
  assignment_id = "hw3",
  semester = "fa25",
  files_under_review = { "pipe.txt" },
  session_privkey = %q,
  session_pubkey_hex = %q,
  now = function() return "2026-05-19T14:30:14.000Z" end,
})
local f = assert(io.open(%q, "w"))
f:write(res.kind .. "|" .. tostring(res.warnings and res.warnings.unreadable_in_scope_file))
f:close()
]],
      REPO_ROOT,
      REPO_ROOT,
      workspace,
      provenance_dir,
      fixture.kp.private_key,
      fixture.kp.public_key_hex,
      out_file
    )
    write_raw_file(child_script, script)

    local job = vim.fn.jobstart({ "nvim", "-l", child_script })
    assert.is_true(job > 0, "failed to start child nvim -l process")

    local waited = vim.fn.jobwait({ job }, 5000)
    if waited[1] == -1 then
      pcall(vim.fn.jobstop, job)
      assert.is_true(false, "seal_bundle HUNG on a FIFO: did not return within 5s")
      return
    end

    assert.is_true(vim.fn.filereadable(out_file) == 1, "child process produced no result file")
    local lines = vim.fn.readfile(out_file)
    assert.equals("ok|true", lines[1])

    local files, by_path = submission_files_of(provenance_dir)
    assert.equals(0, #files)
    assert.is_nil(by_path["pipe.txt"])
  end)
end)
