--- recording_session.start (Plan 4 CAPSTONE). Real headless Neovim, real
--- vim.uv I/O, real temp workspace/provenance dirs — the composition under
--- test is exactly the wiring seam (keypair -> session.start -> writer ->
--- doc-wiring -> heartbeat -> seal/stop), so it is exercised end-to-end the
--- same way doc_wiring_spec.lua and seal_spec.lua exercise their own real
--- Neovim seams. `env.uuid` is injected for a deterministic logical
--- session_id; the `.slog` filename uuid is intentionally left to the real
--- `vim.uv.random` draw (that's the two-uuid rule under test).
local recording_session = require("provenance.recorder.session.recording_session")
local core_clock = require("provenance.core.clock")
local core_ndjson = require("provenance.core.ndjson")
local core_chain_validator = require("provenance.core.chain_validator")
local core_hash_chain = require("provenance.core.hash_chain")
local core_meta = require("provenance.core.meta")
local core_bundle = require("provenance.core.bundle")

local AUGROUP_NAME = "ProvenanceDocWiring"

--- Track everything created by a test so it can be torn down afterward:
--- session ALWAYS stopped (idempotent, safe even if the test already
--- stopped it), buffers wiped, temp dirs deleted.
local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, session = nil }

  function scratch.workspace()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    table.insert(scratch.dirs, dir)
    return dir
  end

  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
  end

  --- Opens `path` in the current window via :edit and returns the bufnr.
  --- Tracked for wipeout in teardown().
  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  function scratch.teardown()
    if scratch.session then
      scratch.session.stop()
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
  end

  return scratch
end

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

--- A minimal dev manifest with a real 128-hex signature (encrypt_privkey
--- only uses it as HKDF input material, so any 128-hex string works — same
--- convention as meta_writer_spec.lua / seal_spec.lua).
local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }
end

describe("recording_session.start", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("session.start is the first .slog line: seq 0, GENESIS prev_hash", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
      env = { uuid = function() return "fixed-session-id" end },
    })

    scratch.session.stop() -- flush so the .slog is on disk

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)
    assert.is_true(#parsed.value >= 1)

    local first = parsed.value[1]
    assert.equals("session.start", first.kind)
    assert.equals(0, first.seq)
    assert.equals(core_hash_chain.GENESIS_PREV_HASH, first.prev_hash)
    assert.equals("fixed-session-id", first.data.session_id)
  end)

  it("writes .slog.meta immediately, validated by core.meta with pubkey + encrypted privkey", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })

    assert.is_true(vim.uv.fs_stat(scratch.session.meta_path) ~= nil)

    local text = read_all(scratch.session.meta_path)
    local decoded = vim.json.decode(text)
    local res = core_meta.validate_shape(decoded)
    assert.is_true(res.ok)
    assert.equals(64, #res.value.session_pubkey)
    assert.equals(scratch.session.public_key_hex, res.value.session_pubkey)
    assert.is_not_nil(res.value.encrypted_session_privkey)
    assert.equals("xchacha20-poly1305-hkdf-sha256-v1", res.value.encrypted_session_privkey.algorithm)
  end)

  it("two-uuid rule: the .slog filename uuid differs from the logical session_id", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
      env = { uuid = function() return "fixed-session-id" end },
    })

    assert.equals("fixed-session-id", scratch.session.session_id)

    local filename = vim.fn.fnamemodify(scratch.session.slog_path, ":t")
    local file_uuid = filename:match("^session%-(.+)%.slog$")
    assert.is_not_nil(file_uuid)
    assert.are_not.equals(scratch.session.session_id, file_uuid)
  end)

  it("typing in a recordable buffer produces a doc.change chained onto session.start", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "edited" })

    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    local found_change = false
    for _, e in ipairs(parsed.value) do
      if e.kind == "doc.change" then
        found_change = true
      end
    end
    assert.is_true(found_change)

    local chain = core_chain_validator.validate_chain(parsed.value)
    assert.is_true(chain.ok)
  end)

  it("stop() appends session.end (reason=deactivate) as the last entry; chain validates; idempotent", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })

    scratch.session.stop()
    -- Idempotent: a second call must not error and must not append again.
    assert.has_no.errors(function() scratch.session.stop() end)

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    local last = parsed.value[#parsed.value]
    assert.equals("session.end", last.kind)
    assert.equals("deactivate", last.data.reason)

    local end_count = 0
    for _, e in ipairs(parsed.value) do
      if e.kind == "session.end" then
        end_count = end_count + 1
      end
    end
    assert.equals(1, end_count)

    local chain = core_chain_validator.validate_chain(parsed.value)
    assert.is_true(chain.ok)
  end)

  it("stop() with an explicit reason is carried through to session.end.data.reason", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })

    scratch.session.stop("seal")

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    local last = parsed.value[#parsed.value]
    assert.equals("session.end", last.kind)
    assert.equals("seal", last.data.reason)
  end)

  it("teardown: doc-wiring augroup is removed and no autocmds remain after stop()", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })

    scratch.session.stop()

    local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = AUGROUP_NAME })
    assert.is_true(not ok or #autocmds == 0)
  end)

  it("creates provenance_dir itself when it does not already exist on disk", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    -- Deliberately NOT pre-created (unlike every other test in this file):
    -- this is the regression case for first activation of a fresh workspace.
    assert.is_nil(vim.uv.fs_stat(provenance_dir))

    assert.has_no.errors(function()
      scratch.session = recording_session.start({
        workspace = workspace,
        provenance_dir = provenance_dir,
        manifest = dev_manifest(),
        clock = core_clock.fixed(0, 0),
      })
    end)

    assert.is_true(vim.uv.fs_stat(provenance_dir) ~= nil)
    assert.is_true(vim.uv.fs_stat(scratch.session.meta_path) ~= nil)

    scratch.session.stop()
  end)

  it("seal() flushes and produces a bundle whose manifest verifies against the session pubkey", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\n")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })

    scratch.edit(path)

    local result = scratch.session.seal({ now = function() return "2026-05-19T14:30:00.000Z" end })

    assert.equals("ok", result.kind)
    assert.is_true(vim.uv.fs_stat(result.bundle_path) ~= nil)

    local manifest_json_text = read_all(provenance_dir .. "/manifest.json")
    local sig_text = read_all(provenance_dir .. "/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_json_text, sig_text, scratch.session.public_key_hex))
  end)
end)
