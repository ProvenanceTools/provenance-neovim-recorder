--- recording_controller.start (Plan 9 CAPSTONE). Real headless Neovim, real
--- vim.uv I/O, a real temp workspace + .provenance/, and the full signal
--- fan-out composed into ONE live session (paste, external-change, terminal/
--- git/snapshot, clock-skew, doc-wiring, heartbeat). The controller IS a
--- recording_session started with enable_signals=true, so this exercises the
--- exact production wiring recorder/init.lua starts on activation.
---
--- The assertion that matters: a genuine editing session drives EVERY expected
--- event kind into the single hash-chained `.slog`, the whole chain validates,
--- and stop() tears every background resource down with no leaked augroup or
--- libuv handle (headless must exit clean).
local recording_controller = require("provenance.recorder.session.recording_controller")
local core_clock = require("provenance.core.clock")
local core_ndjson = require("provenance.core.ndjson")
local core_chain_validator = require("provenance.core.chain_validator")

--- Redirect the "+"/"*" registers off the shared OS pasteboard onto a private
--- in-process store, so a real vim.paste in this spec never races the
--- concurrently-running paste specs (see paste_assembly_spec.lua for the full
--- rationale). Only the STORAGE backing the registers is redirected; the real
--- Neovim register API still runs.
local function install_local_clipboard()
  local store = { ["+"] = { {}, "v" }, ["*"] = { {}, "v" } }
  vim.g.clipboard = {
    name = "ProvenanceControllerTestLocalClipboard",
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

  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  function scratch.teardown()
    if scratch.session then
      pcall(scratch.session.stop)
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
    pcall(vim.fn.setreg, "+", "")
    pcall(vim.fn.setreg, "*", "")
  end

  return scratch
end

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

--- Dev manifest: sig is only HKDF input material for encrypt_privkey, so any
--- 128-hex string works (same convention as recording_session_spec.lua).
local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }
end

local function group_gone(name)
  local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = name })
  return (not ok) or #autocmds == 0
end

describe("recording_controller.start (full-signals capstone)", function()
  local scratch

  before_each(function()
    install_local_clipboard()
    scratch = new_scratch()
    vim.fn.setreg("+", "")
    vim.fn.setreg("*", "")
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("drives every signal kind into one valid chain, then tears everything down", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    local reviewed_abs = workspace .. "/foo.txt"
    scratch.write_file(reviewed_abs, "hello\n")

    -- Full-signals session (enable_signals forced true by the controller).
    scratch.session = recording_controller.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.system(),
    })

    -- _signals is the Plan 9 test seam; nil would mean signals weren't wired.
    assert.is_not_nil(scratch.session._signals)

    -- doc.open (+ seeds the external-change baseline): :edit after start()
    -- fires BufReadPost live (catch-up only covers already-open buffers).
    local buf = scratch.edit(reviewed_abs)

    -- doc.change: a short (<30 char) typed edit routes to doc.change, not paste.
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "edited" })

    -- paste: a real vim.paste of a >=30-char single-line string, through the
    -- real intercept + doc-wiring router (private clipboard isolates the reg).
    local clip = string.rep("p", 32)
    assert.is_true(#clip >= 30)
    vim.fn.setreg("+", clip)
    vim.paste({ clip }, -1)

    -- doc.save: :write fires BufWritePost. reconcile_save resets the expected
    -- model to the just-written bytes, so this clean save does NOT itself emit
    -- an external change.
    vim.cmd("write")

    -- fs.external_change (deterministic drive, per task brief): clobber the
    -- file on disk with different bytes AFTER the clean save, then run Path 1
    -- directly via the coordinator seam. save_time_checker reads the on-disk
    -- bytes, sees they differ from the expected model, and emits exactly one
    -- fs.external_change through the live host.emit into the same chain.
    scratch.write_file(reviewed_abs, "externally clobbered contents\n")
    scratch.session._signals.coordinator.check_after_save("foo.txt", reviewed_abs)

    -- session.heartbeat: force a deterministic tick (no real timer wait).
    scratch.session._signals.heartbeat._tick()

    -- session.end + full teardown.
    scratch.session.stop()

    -- ---- The .slog contains every expected kind, and the chain validates ----
    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

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
      "session.heartbeat",
      "session.end",
    }
    for _, kind in ipairs(expected_kinds) do
      assert.is_true(
        (seen[kind] or 0) >= 1,
        "expected at least one '" .. kind .. "' entry in the .slog (kinds seen: " .. vim.inspect(seen) .. ")"
      )
    end

    local chain = core_chain_validator.validate_chain(parsed.value)
    assert.is_true(chain.ok)

    -- ---- Teardown: no leaked augroups from any signal ----
    assert.is_number(scratch.session._doc_wiring_augroup_id)
    assert.is_true(group_gone(scratch.session._doc_wiring_augroup_id), "ProvenanceDocWiring augroup leaked")
    assert.is_true(group_gone("ProvenanceTerminal"), "ProvenanceTerminal augroup leaked")
    assert.is_number(scratch.session._external_change_augroup_id)
    assert.is_true(
      group_gone(scratch.session._external_change_augroup_id),
      "ProvenanceExternalChange augroup leaked"
    )

    -- stop() is idempotent.
    assert.has_no.errors(function()
      scratch.session.stop()
    end)
  end)
end)
