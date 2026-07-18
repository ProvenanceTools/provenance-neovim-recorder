--- Plan 4 Task 10 — headless LOCAL gate for the same end-to-end path
--- exercised by scripts/e2e/produce_bundle.lua (real recording_session.start
--- -> real doc.open/doc.change/doc.save via :edit/:write -> seal), asserting
--- only the LOCAL invariants that don't require the real monorepo analyzer
--- (this spec is part of `make test` and must stay self-contained):
---   - seal() returns kind == "ok"
---   - manifest.json + manifest.sig verify against the session pubkey
---   - the sealed .slog's hash chain validates
---   - the produced zip is a clean archive (`unzip -t`)
---   - the zip lists manifest.json, manifest.sig, the .slog, its .slog.meta,
---     and the reviewed file
---
--- Cross-language acceptance by the REAL analysis-core is proven separately
--- by scripts/e2e/run_e2e.sh (not run as part of `make test` — it depends on
--- a sibling monorepo checkout).
local recording_session = require("provenance.recorder.session.recording_session")
local recording_controller = require("provenance.recorder.session.recording_controller")
local core_clock = require("provenance.core.clock")
local core_bundle = require("provenance.core.bundle")
local core_ndjson = require("provenance.core.ndjson")
local core_chain_validator = require("provenance.core.chain_validator")

local function unzip_available()
  return vim.fn.executable("unzip") == 1
end

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "src/main.py" },
  }
end

describe("e2e: recording_session.start -> real doc wiring -> seal", function()
  local workspace, provenance_dir, buf, session

  before_each(function()
    workspace = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(workspace, "p")
    provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    buf = nil
    session = nil
  end)

  after_each(function()
    if session then
      session.stop()
    end
    if buf and vim.api.nvim_buf_is_valid(buf) then
      pcall(vim.cmd, "bwipeout! " .. buf)
    end
    if workspace then
      pcall(vim.fn.delete, workspace, "rf")
    end
  end)

  it("seals a bundle whose manifest verifies, chain validates, and zip is clean", function()
    if not unzip_available() then
      pending("unzip not available on this machine")
      return
    end

    local reviewed_rel = "src/main.py"
    local reviewed_abs = workspace .. "/" .. reviewed_rel
    vim.fn.mkdir(vim.fn.fnamemodify(reviewed_abs, ":h"), "p")
    local rf = assert(io.open(reviewed_abs, "w"))
    rf:write("print('hello')\n")
    rf:close()

    session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })

    -- Drive doc.open/doc.change/doc.save through the LIVE wiring (real
    -- :edit / nvim_buf_set_lines / :write), not a hand-built fixture.
    vim.cmd("edit " .. vim.fn.fnameescape(reviewed_abs))
    buf = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "print('edited by e2e spec')" })
    vim.cmd("write")

    local result = session.seal({ now = function() return "2026-05-19T14:30:00.000Z" end })

    assert.equals("ok", result.kind)
    assert.is_true(vim.uv.fs_stat(result.bundle_path) ~= nil)

    -- manifest.json / manifest.sig verify against the session pubkey.
    local manifest_json_text = read_all(provenance_dir .. "/manifest.json")
    local sig_text = read_all(provenance_dir .. "/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_json_text, sig_text, session.public_key_hex))

    -- The sealed .slog's hash chain validates.
    local slog_text = read_all(session.slog_path)
    local parsed = core_ndjson.parse_entries(slog_text)
    assert.is_true(parsed.ok)
    local chain = core_chain_validator.validate_chain(parsed.value)
    assert.is_true(chain.ok)

    -- The zip is a clean archive.
    local test_out = vim.fn.system({ "unzip", "-t", result.bundle_path })
    assert.equals(0, vim.v.shell_error, test_out)
    assert.is_truthy(test_out:find("No errors detected"))

    -- The zip lists manifest.json/manifest.sig/the .slog/.slog.meta/the
    -- reviewed file.
    local slog_name = vim.fn.fnamemodify(session.slog_path, ":t")
    local meta_name = vim.fn.fnamemodify(session.meta_path, ":t")
    local list_out = vim.fn.system({ "unzip", "-l", result.bundle_path })
    assert.equals(0, vim.v.shell_error)
    assert.is_truthy(list_out:find("manifest.json", 1, true))
    assert.is_truthy(list_out:find("manifest.sig", 1, true))
    assert.is_truthy(list_out:find(slog_name, 1, true))
    assert.is_truthy(list_out:find(meta_name, 1, true))
    assert.is_truthy(list_out:find(reviewed_rel, 1, true))
  end)
end)

--- Plan 9 Task 4 — the FULL-SIGNALS counterpart of the minimal-session test
--- above (mirrors scripts/e2e/produce_full_signals_bundle.lua exactly), but
--- asserting only the LOCAL invariants that don't require the real monorepo
--- analyzer (this spec is part of `make test`):
---   - seal() returns kind == "ok"
---   - manifest.json + manifest.sig verify against the session pubkey
---   - the sealed .slog's hash chain validates
---   - the .slog contains the full expected signal-kind set
---   - the produced zip is a clean archive (`unzip -t`)
---
--- Cross-language acceptance of a full-signals bundle by the REAL
--- analysis-core is proven separately by scripts/e2e/run_full_e2e.sh (not
--- run as part of `make test` — it depends on a sibling monorepo checkout).
local function install_full_signals_local_clipboard()
  local store = { ["+"] = { {}, "v" }, ["*"] = { {}, "v" } }
  vim.g.clipboard = {
    name = "ProvenanceFullSignalsE2ESpecLocalClipboard",
    copy = {
      ["+"] = function(lines, regtype)
        store["+"] = { lines, regtype }
      end,
      ["*"] = function(lines, regtype)
        store["*"] = { lines, regtype }
      end,
    },
    paste = {
      ["+"] = function()
        return store["+"]
      end,
      ["*"] = function()
        return store["*"]
      end,
    },
  }
end

describe("e2e: recording_controller.start (full-signals) -> seal (local gates)", function()
  local workspace, provenance_dir, buf, term_buf, session

  before_each(function()
    install_full_signals_local_clipboard()
    vim.fn.setreg("+", "")
    vim.fn.setreg("*", "")

    workspace = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(workspace, "p")
    provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    buf = nil
    term_buf = nil
    session = nil
  end)

  after_each(function()
    if session then
      pcall(session.stop)
    end
    if buf and vim.api.nvim_buf_is_valid(buf) then
      pcall(vim.cmd, "bwipeout! " .. buf)
    end
    if term_buf and vim.api.nvim_buf_is_valid(term_buf) then
      pcall(vim.cmd, "bwipeout! " .. term_buf)
    end
    if workspace then
      pcall(vim.fn.delete, workspace, "rf")
    end
    pcall(vim.fn.setreg, "+", "")
    pcall(vim.fn.setreg, "*", "")
  end)

  it("drives every signal kind, then seals a bundle whose manifest verifies, chain validates, and zip is clean", function()
    if not unzip_available() then
      pending("unzip not available on this machine")
      return
    end

    local reviewed_rel = "src/main.py"
    local reviewed_abs = workspace .. "/" .. reviewed_rel
    vim.fn.mkdir(vim.fn.fnamemodify(reviewed_abs, ":h"), "p")
    local rf = assert(io.open(reviewed_abs, "w"))
    rf:write("print('hello')\n")
    rf:close()

    -- Small checkpoint_interval so a signed checkpoint fires during this
    -- short session (session.start + ext.snapshot + doc.open == 3 entries
    -- already schedules one).
    session = recording_controller.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.system(),
      checkpoint_interval = 3,
    })
    assert.is_not_nil(session._signals)

    -- doc.open (+ seeds the external-change baseline).
    vim.cmd("edit " .. vim.fn.fnameescape(reviewed_abs))
    buf = vim.api.nvim_get_current_buf()

    -- doc.change: a short (<30 char) typed edit routes to doc.change, not
    -- paste (PASTE_MIN_INSERT_CHARS is 30).
    vim.api.nvim_buf_set_lines(buf, 1, 1, false, { "# e2e edit" })

    -- paste: a real vim.paste of a >=30-char single-line string, through the
    -- real intercept + doc-wiring router.
    local clip = string.rep("p", 32)
    vim.fn.setreg("+", clip)
    vim.paste({ clip }, -1)

    -- doc.save: :write fires BufWritePost. reconcile_save resets the
    -- expected model to the just-written bytes, so this clean save does not
    -- itself emit an external change.
    vim.cmd("write")

    -- fs.external_change (deterministic drive): clobber the file on disk
    -- with different bytes AFTER the clean save, then run Path 1 directly
    -- via the coordinator seam. The file is NOT touched again after this,
    -- so the final on-disk bytes match the last recorded state.
    local cf = assert(io.open(reviewed_abs, "w"))
    cf:write("print('clobbered externally')\n")
    cf:close()
    session._signals.coordinator.check_after_save(reviewed_rel, reviewed_abs)

    -- terminal.open: synthetic TermOpen fire on a scratch buffer with
    -- terminal-shaped buffer-locals (mirrors terminal_wiring_spec.lua).
    -- Never spawns a real shell/PTY.
    term_buf = vim.api.nvim_create_buf(false, true)
    vim.b[term_buf].terminal_job_id = 4242
    vim.b[term_buf].term_title = "/bin/fake-shell"
    vim.api.nvim_exec_autocmds("TermOpen", { group = "ProvenanceTerminal", buffer = term_buf })

    -- session.heartbeat: force a deterministic tick (no real timer wait).
    session._signals.heartbeat._tick()

    local result = session.seal({ now = function() return "2026-05-19T14:30:00.000Z" end })

    assert.equals("ok", result.kind)
    assert.is_true(vim.uv.fs_stat(result.bundle_path) ~= nil)

    -- manifest.json / manifest.sig verify against the session pubkey.
    local manifest_json_text = read_all(provenance_dir .. "/manifest.json")
    local sig_text = read_all(provenance_dir .. "/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_json_text, sig_text, session.public_key_hex))

    -- The sealed .slog's hash chain validates.
    local slog_text = read_all(session.slog_path)
    local parsed = core_ndjson.parse_entries(slog_text)
    assert.is_true(parsed.ok)
    local chain = core_chain_validator.validate_chain(parsed.value)
    assert.is_true(chain.ok)

    -- The .slog contains the full expected signal-kind set.
    local seen = {}
    for _, e in ipairs(parsed.value) do
      seen[e.kind] = (seen[e.kind] or 0) + 1
    end
    local expected_kinds = {
      "session.start",
      "ext.snapshot",
      "doc.open",
      "doc.change",
      "paste",
      "doc.save",
      "fs.external_change",
      "terminal.open",
      "session.heartbeat",
    }
    for _, kind in ipairs(expected_kinds) do
      assert.is_true(
        (seen[kind] or 0) >= 1,
        "expected at least one '" .. kind .. "' entry in the .slog (kinds seen: " .. vim.inspect(seen) .. ")"
      )
    end

    -- The zip is a clean archive.
    local test_out = vim.fn.system({ "unzip", "-t", result.bundle_path })
    assert.equals(0, vim.v.shell_error, test_out)
    assert.is_truthy(test_out:find("No errors detected"))
  end)
end)
