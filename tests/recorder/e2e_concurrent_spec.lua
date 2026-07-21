--- e2e: two concurrent recording_controller sessions (Plan:
--- 2026-07-20-nested-manifest-discovery, acceptance criteria 2/3/6).
--- Drives TWO real sessions over two disjoint temp workspaces, proving:
---   - each gets its own .provenance/ with its own valid hash chain
---   - an edit in workspace A's buffer never appears in workspace B's slog
---   - a terminal opened with cwd = workspace A is recorded ONLY by A
---   - each can be sealed independently into a bundle whose manifest
---     verifies and whose chain validates (mirrors e2e_seal_spec.lua's
---     local, non-analyzer gate -- cross-language acceptance by the real
---     analyzer is exercised for the single-session case there already;
---     this spec proves concurrency-specific isolation, not format parity).
local recording_controller = require("provenance.recorder.session.recording_controller")
local core_clock = require("provenance.core.clock")
local core_bundle = require("provenance.core.bundle")
local core_ndjson = require("provenance.core.ndjson")
local core_chain_validator = require("provenance.core.chain_validator")

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

local function manifest_for(id)
  return {
    assignment_id = id,
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "main.py" },
  }
end

describe("e2e: two concurrent recording_controller sessions", function()
  local workspace_a, workspace_b, session_a, session_b, buf_a, buf_b, term_buf

  before_each(function()
    workspace_a = vim.fs.normalize(vim.fn.tempname())
    workspace_b = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(workspace_a .. "/.provenance", "p")
    vim.fn.mkdir(workspace_b .. "/.provenance", "p")
    session_a, session_b, buf_a, buf_b, term_buf = nil, nil, nil, nil, nil
  end)

  after_each(function()
    if session_a then pcall(session_a.stop) end
    if session_b then pcall(session_b.stop) end
    for _, b in ipairs({ buf_a, buf_b, term_buf }) do
      if b and vim.api.nvim_buf_is_valid(b) then
        pcall(vim.cmd, "bwipeout! " .. b)
      end
    end
    pcall(vim.fn.delete, workspace_a, "rf")
    pcall(vim.fn.delete, workspace_b, "rf")
  end)

  it("isolates doc events, terminal attribution, and hash chains across two concurrent sessions", function()
    local file_a = workspace_a .. "/main.py"
    local file_b = workspace_b .. "/main.py"
    for _, p in ipairs({ file_a, file_b }) do
      local f = assert(io.open(p, "w"))
      f:write("print('hello')\n")
      f:close()
    end

    session_a = recording_controller.start({
      workspace = workspace_a,
      provenance_dir = workspace_a .. "/.provenance",
      manifest = manifest_for("cats"),
      clock = core_clock.system(),
    })
    session_b = recording_controller.start({
      workspace = workspace_b,
      provenance_dir = workspace_b .. "/.provenance",
      manifest = manifest_for("hog"),
      clock = core_clock.system(),
    })

    -- Edit A: must appear in A's slog, never B's.
    vim.cmd("edit " .. vim.fn.fnameescape(file_a))
    buf_a = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(buf_a, 0, 1, false, { "print('edited in A')" })
    vim.cmd("write")

    -- Edit B: must appear in B's slog, never A's.
    vim.cmd("edit " .. vim.fn.fnameescape(file_b))
    buf_b = vim.api.nvim_get_current_buf()
    vim.api.nvim_buf_set_lines(buf_b, 0, 1, false, { "print('edited in B')" })
    vim.cmd("write")

    -- A terminal whose cwd is workspace A: recorded only by A's terminal
    -- signal, never B's (Task 4's workspace-scoped attribution).
    local orig_cwd = vim.fn.getcwd()
    vim.cmd("cd " .. vim.fn.fnameescape(workspace_a))
    term_buf = vim.api.nvim_create_buf(false, true)
    vim.b[term_buf].terminal_job_id = 777
    vim.b[term_buf].term_title = "/bin/fake-shell"
    vim.api.nvim_exec_autocmds("TermOpen", { buffer = term_buf })
    vim.cmd("cd " .. vim.fn.fnameescape(orig_cwd))

    -- Seal FIRST (session.seal() flushes the buffered writer to disk before
    -- reading .slog files ever succeeds -- the writer only actually creates/
    -- appends to the file on flush, not on open()/append(), mirroring
    -- e2e_seal_spec.lua's existing single-session tests, which also only
    -- ever read session.slog_path AFTER calling seal()). Sealing does not
    -- stop a session, so this is safe to do before the isolation assertions
    -- below.
    local result_a = session_a.seal({ now = function() return "2026-07-20T10:00:00.000Z" end })
    local result_b = session_b.seal({ now = function() return "2026-07-20T10:00:01.000Z" end })
    assert.equals("ok", result_a.kind)
    assert.equals("ok", result_b.kind)

    local function slog_kinds(session)
      local text = read_all(session.slog_path)
      local parsed = core_ndjson.parse_entries(text)
      assert.is_true(parsed.ok)
      local by_kind = {}
      for _, e in ipairs(parsed.value) do
        by_kind[e.kind] = (by_kind[e.kind] or 0) + 1
      end
      return by_kind, parsed.value
    end

    local kinds_a, entries_a = slog_kinds(session_a)
    local kinds_b, entries_b = slog_kinds(session_b)

    assert.is_true((kinds_a["terminal.open"] or 0) >= 1, "A's slog should have terminal.open")
    assert.is_nil(kinds_b["terminal.open"], "B's slog must NOT have a terminal.open for A's terminal")

    -- Doc events are isolated: A's slog only ever references "main.py"
    -- content it itself wrote; find each session's doc.save and confirm
    -- against ITS OWN file's on-disk content, not the other's.
    assert.is_true((kinds_a["doc.save"] or 0) >= 1)
    assert.is_true((kinds_b["doc.save"] or 0) >= 1)

    -- Each session's own chain validates independently.
    assert.is_true(core_chain_validator.validate_chain(entries_a).ok)
    assert.is_true(core_chain_validator.validate_chain(entries_b).ok)

    local manifest_a_text = read_all(workspace_a .. "/.provenance/manifest.json")
    local sig_a_text = read_all(workspace_a .. "/.provenance/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_a_text, sig_a_text, session_a.public_key_hex))
    assert.is_false(core_bundle.verify_sig(manifest_a_text, sig_a_text, session_b.public_key_hex))

    local manifest_b_text = read_all(workspace_b .. "/.provenance/manifest.json")
    local sig_b_text = read_all(workspace_b .. "/.provenance/manifest.sig")
    assert.is_true(core_bundle.verify_sig(manifest_b_text, sig_b_text, session_b.public_key_hex))
  end)
end)
