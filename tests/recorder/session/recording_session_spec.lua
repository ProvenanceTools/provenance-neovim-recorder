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

--- The capture policy, end to end through the real composition (program spec §4).
--- recording_session resolves the policy ONCE from the verified manifest and
--- hands the compiled gate to SessionHost, which is the single chokepoint every
--- wiring module's emit passes through.
describe("recording_session capture policy", function()
  local core_manifest = require("provenance.core.manifest")
  local core_capture_policy = require("provenance.core.capture_policy")
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  local function start(manifest, extra)
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local opts = {
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest,
      clock = core_clock.fixed(0, 0),
      env = { uuid = function() return "fixed-session-id" end },
    }
    for k, v in pairs(extra or {}) do
      opts[k] = v
    end
    scratch.session = recording_session.start(opts)
    return scratch.session
  end

  local function entries_of(session)
    session.stop()
    local parsed = core_ndjson.parse_entries(read_all(session.slog_path))
    assert.is_true(parsed.ok)
    return parsed.value
  end

  --- A 2.0 manifest carrying `policy`. Its signature is not verified here --
  --- activation already did that; recording_session composes a manifest it is
  --- given. What matters is that the POLICY is honoured and the chain stays
  --- intact.
  local function v2_manifest_with(capture)
    return {
      format_version = "2.0",
      course_id = "berkeley-cs61b",
      assignment_id = "hw3",
      semester = "fa25",
      issued_at = "2026-01-01T00:00:00Z",
      files_under_review = { "foo.txt" },
      collaboration = "solo",
      submission = "bundle",
      scope = "directory",
      policy = { capture = capture },
      sig = ("ab"):rep(64),
    }
  end

  it("a 2.0 all-off policy suppresses gated kinds, and the chain still validates", function()
    local session = start(v2_manifest_with({
      selection_change = false,
      focus_change = false,
      terminal = false,
    }))

    -- Drive the gated kinds straight at the host's emit seam, which is exactly
    -- what every wiring module does.
    for _, kind in ipairs({ "selection.change", "focus.change", "terminal.open", "terminal.command" }) do
      session._host.emit(kind, { probe = kind })
    end
    -- Floor kinds, which no policy can reach.
    session._host.emit("doc.change", { probe = "doc.change" })
    session._host.emit("doc.open", { probe = "doc.open" })

    local entries = entries_of(session)
    for _, entry in ipairs(entries) do
      assert.is_nil(
        core_capture_policy.POLICY_GATED_EVENT_KINDS[entry.kind],
        entry.kind .. " was disabled by policy and must not appear"
      )
    end
    for i, entry in ipairs(entries) do
      assert.equals(i - 1, entry.seq, "suppressed events must consume no seq")
    end
    assert.is_true(core_chain_validator.validate_chain(entries).ok)
  end)

  it("a 1.x manifest with a stapled policy is IGNORED — students get no off switch", function()
    -- Below 2.0 the policy block is not inside the signed payload, so a student
    -- could staple this onto a genuinely signed 1.x manifest.
    local m = dev_manifest()
    m.policy = { capture = { selection_change = false, terminal = false } }

    local session = start(m)
    session._host.emit("selection.change", { probe = 1 })
    session._host.emit("terminal.open", { probe = 2 })

    local kinds = {}
    for _, entry in ipairs(entries_of(session)) do
      kinds[entry.kind] = true
    end
    assert.is_true(kinds["selection.change"], "a 1.x policy must not disable capture")
    assert.is_true(kinds["terminal.open"], "a 1.x policy must not disable capture")
  end)

  it("session.heartbeat is on the floor: it survives an all-off policy", function()
    local session = start(v2_manifest_with({
      selection_change = false,
      focus_change = false,
      terminal = false,
      heartbeat_interval_ms = 120000,
    }))
    -- Driven at the gate, which is where the floor is enforced -- the heartbeat
    -- module itself is not policy-aware and does not need to be.
    session._host.emit("session.heartbeat", { focused = true })

    local kinds = {}
    for _, entry in ipairs(entries_of(session)) do
      kinds[entry.kind] = true
    end
    assert.is_true(kinds["session.heartbeat"], "only the heartbeat INTERVAL is tunable, never its existence")
  end)

  it("honours the policy's clamped heartbeat_interval_ms", function()
    -- The value below is out of range on both attempts; resolve() clamps it, and
    -- the clamped value is what reaches the timer.
    local session = start(v2_manifest_with({ heartbeat_interval_ms = 1000 }))
    assert.equals(core_capture_policy.HEARTBEAT_INTERVAL_MIN_MS, session._policy.heartbeat_interval_ms)

    scratch.session = nil
    session.stop()

    local session2 = start(v2_manifest_with({ heartbeat_interval_ms = 999999 }))
    assert.equals(core_capture_policy.HEARTBEAT_INTERVAL_MAX_MS, session2._policy.heartbeat_interval_ms)
  end)

  it("a RETIRED capture key in a live 2.0 manifest is inert", function()
    -- doc_open_close and inline_content were removed. A manifest still carrying
    -- them must behave as if it carried unknown keys: doc.open still recorded,
    -- paste content still intact.
    local session = start(v2_manifest_with({ doc_open_close = false, inline_content = false }))
    assert.same(core_capture_policy.DEFAULTS, session._policy)

    session._host.emit("doc.open", { probe = "doc.open" })
    session._host.emit("paste", { length = 6, sha256 = ("d"):rep(64), content = "secret" })

    local by_kind = {}
    for _, entry in ipairs(entries_of(session)) do
      by_kind[entry.kind] = entry
    end
    assert.is_not_nil(by_kind["doc.open"], "doc.open is floor; a retired key must not suppress it")
    assert.equals("secret", by_kind["paste"].data.content, "no policy may strip paste content")
  end)

  it("a 1.x session resolves to the v1.x capture set, unchanged", function()
    local session = start(dev_manifest())
    assert.same(core_capture_policy.DEFAULTS, session._policy)
  end)

  it("session.start carries the manifest and host block into the log", function()
    local v2 = core_manifest.parse(
      table.concat(vim.fn.readfile(
        vim.fn.fnamemodify(debug.getinfo(1, "S").source:sub(2), ":h") .. "/../fixtures/dev-manifest-v2.json"
      ), "\n")
    ).value

    local entries = entries_of(start(v2))
    local start_entry = entries[1]
    assert.equals("session.start", start_entry.kind)
    assert.equals("neovim", start_entry.data.host.editor)
    assert.equals("", start_entry.data.host.editor_build)
    assert.equals("2.0", start_entry.data.manifest.format_version)
    assert.equals("dev-course", start_entry.data.manifest.course_id)
    assert.is_table(start_entry.data.manifest.course_cert)
    assert.is_nil(start_entry.data.identity)
  end)
end)
