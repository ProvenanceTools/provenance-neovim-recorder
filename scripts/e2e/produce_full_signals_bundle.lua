--- Plan 9 Task 4 (SUCCESS CRITERION): FULL-SIGNALS headless driver that
--- produces a real sealed submission bundle by exercising the LIVE
--- recording_controller wiring (recording_session with enable_signals=true)
--- exactly the way a student's editor session would — activation manifest on
--- disk, a real doc.open/doc.change/doc.save cycle against a reviewed file,
--- a real paste, an externally-clobbered file detected via the coordinator,
--- a synthetic terminal.open, a real git commit + a git.event, a forced
--- session.heartbeat, and a checkpoint (small checkpoint_interval) — then
--- seal(). The resulting `.zip` is copied to a stable name under
--- $PROVNVIM_E2E_OUT so scripts/verify-bundle-with-analyzer.mjs (run in the
--- real Provenance monorepo) can load it via analysis-core's loadBundle +
--- runValidation.
---
--- This is STRONGER than scripts/e2e/produce_bundle.lua (Plan 4 Task 10),
--- which only drives doc.open/doc.change/doc.save through the lean core
--- (enable_signals=false). Here every signal kind lands in the same
--- hash-chained `.slog`, so the real analyzer's per-check gates (especially
--- doc_save_hashes / submitted_code_match) are exercised against paste and
--- external-change reconstruction, not just a clean edit.
---
--- NOT a plenary spec — this is a throwaway CLI-style script, run via:
---   nvim --headless -u tests/minimal_init.lua -l scripts/e2e/produce_full_signals_bundle.lua
--- (tests/minimal_init.lua bootstraps the runtimepath, so
--- require("provenance...") resolves the same way it does under `make test`.)
---
--- On success: prints "E2E_FULL_BUNDLE_OK <path>" followed by
--- "E2E_FULL_BUNDLE_KINDS <space-separated distinct event kinds>" and exits 0.
--- On any error: prints the error and os.exit(1).

local function fail(msg)
  io.stderr:write("E2E_FULL_BUNDLE_FAIL: " .. tostring(msg) .. "\n")
  os.exit(1)
end

local ok, err = pcall(function()
  local out_dir = os.getenv("PROVNVIM_E2E_OUT")
  if not out_dir or out_dir == "" then
    error("PROVNVIM_E2E_OUT is not set")
  end
  if vim.fn.isdirectory(out_dir) ~= 1 then
    error("PROVNVIM_E2E_OUT does not exist or is not a directory: " .. out_dir)
  end

  local activation = require("provenance.recorder.activation")
  local core_clock = require("provenance.core.clock")
  local core_ndjson = require("provenance.core.ndjson")
  local recording_controller = require("provenance.recorder.session.recording_controller")

  -- ---------------------------------------------------------------------
  -- 1. Temp workspace with a valid signed .provenance-manifest, built from
  --    the committed dev fixture (tests/conformance/fixtures/manifest.json)
  --    -- same fixture produce_bundle.lua uses, so this exercises the same
  --    activation gate against the real embedded course public key.
  -- ---------------------------------------------------------------------
  local this_file = debug.getinfo(1, "S").source:sub(2)
  local repo_root = vim.fn.fnamemodify(vim.fn.resolve(vim.fn.fnamemodify(this_file, ":p")), ":h:h:h")
  local fixture_path = repo_root .. "/tests/conformance/fixtures/manifest.json"
  local fixture_text = table.concat(vim.fn.readfile(fixture_path, "b"), "\n")
  local fixture = vim.json.decode(fixture_text)
  if type(fixture) ~= "table" or type(fixture.manifest) ~= "table" then
    error("conformance fixture manifest.json missing inner `manifest` object")
  end

  local workspace = vim.fs.normalize(vim.fn.tempname())
  vim.fn.mkdir(workspace, "p")

  local manifest_text = vim.json.encode(fixture.manifest)
  local manifest_file_path = workspace .. "/.provenance-manifest"
  local mf = assert(io.open(manifest_file_path, "w"))
  mf:write(manifest_text)
  mf:close()

  local provenance_dir = workspace .. "/.provenance"
  vim.fn.mkdir(provenance_dir, "p")

  local activated = activation.load_and_verify(workspace)
  if activated.status ~= "active" then
    error("dev fixture manifest failed activation: " .. vim.inspect(activated))
  end
  local manifest = activated.manifest

  -- ---------------------------------------------------------------------
  -- 2. The reviewed file (files_under_review[1] == "src/main.py" in the
  --    fixture). src/util.py, the fixture's other reviewed file, is
  --    deliberately left untouched/absent -- seal.lua degrades an absent
  --    reviewed file to submission_files status "missing" (never an
  --    error), and produce_bundle.lua already proved this degrades
  --    gracefully through the real analyzer (Plan 4 Task 10).
  -- ---------------------------------------------------------------------
  local reviewed_rel = manifest.files_under_review[1]
  if not reviewed_rel then
    error("fixture manifest has no files_under_review entries")
  end
  local reviewed_abs = workspace .. "/" .. reviewed_rel
  vim.fn.mkdir(vim.fn.fnamemodify(reviewed_abs, ":h"), "p")

  local reviewed_content = "print('hello world')\n"
  local rf = assert(io.open(reviewed_abs, "w"))
  rf:write(reviewed_content)
  rf:close()

  -- ---------------------------------------------------------------------
  -- 3. git.event signal: real `git init` + an initial commit BEFORE the
  --    session starts (git_wiring detects the repo once, at start()). A
  --    second commit happens mid-session (step 6 below) to move HEAD, and
  --    `session._signals.git._on_head_change()` is called directly to emit
  --    the git.event deterministically rather than waiting on the real
  --    fs_poll reflog watcher's 2s default interval.
  ---------------------------------------------------------------------
  local git_available = vim.fn.executable("git") == 1
  if git_available then
    local function git(args)
      local cmd = vim.list_extend({ "git", "-C", workspace }, args)
      vim.fn.system(cmd)
      return vim.v.shell_error == 0
    end
    git_available = git({ "init", "-q" })
      and git({ "config", "user.email", "e2e@example.com" })
      and git({ "config", "user.name", "provnvim e2e" })
      and git({ "add", "-A" })
      and git({ "commit", "-q", "-m", "initial" })
    if not git_available then
      io.stderr:write("E2E_FULL_BUNDLE_WARN: git init/commit failed; git.event will be absent (graceful degrade)\n")
    end
  else
    io.stderr:write("E2E_FULL_BUNDLE_WARN: git not on PATH; git.event will be absent (graceful degrade)\n")
  end

  -- ---------------------------------------------------------------------
  -- 4. Start a FULL-SIGNALS session against the activated workspace. Small
  --    checkpoint_interval so a checkpoint fires during this short session
  --    (session.start + ext.snapshot + doc.open == 3 entries already).
  -- ---------------------------------------------------------------------
  local session = recording_controller.start({
    workspace = workspace,
    provenance_dir = provenance_dir,
    manifest = manifest,
    clock = core_clock.system(),
    checkpoint_interval = 3,
  })
  if not session._signals then
    error("recording_controller.start did not populate _signals -- signals were not wired")
  end

  -- ---------------------------------------------------------------------
  -- 5. doc.open / doc.change / paste / doc.save through the LIVE wiring.
  -- ---------------------------------------------------------------------
  vim.cmd("edit " .. vim.fn.fnameescape(reviewed_abs))
  local buf = vim.api.nvim_get_current_buf()

  -- doc.change: a short (<30 char) typed edit routes to doc.change, not
  -- paste (PASTE_MIN_INSERT_CHARS is 30; see paste_classifier.lua).
  vim.api.nvim_buf_set_lines(buf, 1, 1, false, { "# e2e edit" })

  -- paste: a real vim.paste of a >=30-char single-line string, through the
  -- real intercept + doc-wiring router. Redirect "+"/"*" onto a private
  -- in-process clipboard so this never touches (or races) the real OS
  -- pasteboard (mirrors recording_controller_spec.lua's
  -- install_local_clipboard).
  local clipboard_store = { ["+"] = { {}, "v" }, ["*"] = { {}, "v" } }
  vim.g.clipboard = {
    name = "ProvenanceFullSignalsE2ELocalClipboard",
    copy = {
      ["+"] = function(lines, regtype)
        clipboard_store["+"] = { lines, regtype }
      end,
      ["*"] = function(lines, regtype)
        clipboard_store["*"] = { lines, regtype }
      end,
    },
    paste = {
      ["+"] = function()
        return clipboard_store["+"]
      end,
      ["*"] = function()
        return clipboard_store["*"]
      end,
    },
  }
  local clip = string.rep("p", 32)
  vim.fn.setreg("+", clip)
  vim.paste({ clip }, -1)

  -- doc.save: :write fires BufWritePost. reconcile_save resets the expected
  -- model to the just-written bytes, so this clean save does NOT itself
  -- emit an external change.
  vim.cmd("write")

  -- ---------------------------------------------------------------------
  -- 6. fs.external_change (deterministic drive): clobber the reviewed file
  --    on disk with different bytes AFTER the clean save, then run Path 1
  --    directly via the coordinator seam. IMPORTANT: the file is NOT
  --    touched again after this -- the final on-disk bytes are exactly the
  --    clobbered bytes, which is also what fs.external_change's new_hash
  --    records as the last recorded state for this path, so
  --    submitted_code_match's "last recorded hash == submitted bytes"
  --    comparison matches.
  -- ---------------------------------------------------------------------
  local clobbered_content = "print('clobbered externally')\n"
  local cf = assert(io.open(reviewed_abs, "w"))
  cf:write(clobbered_content)
  cf:close()
  session._signals.coordinator.check_after_save(reviewed_rel, reviewed_abs)

  -- ---------------------------------------------------------------------
  -- 7. terminal.open: synthetic TermOpen fire on a scratch buffer with
  --    terminal-shaped buffer-locals (mirrors
  --    tests/recorder/wiring/terminal_wiring_spec.lua). Never spawns a real
  --    shell/PTY -- headless sandboxes often have none available.
  -- ---------------------------------------------------------------------
  local term_buf = vim.api.nvim_create_buf(false, true)
  vim.b[term_buf].terminal_job_id = 4242
  vim.b[term_buf].term_title = "/bin/fake-shell"
  vim.api.nvim_exec_autocmds("TermOpen", { group = "ProvenanceTerminal", buffer = term_buf })

  -- ---------------------------------------------------------------------
  -- 8. git.event: a second commit (moves HEAD via the reflog), then a
  --    deterministic _on_head_change() call so the event lands without
  --    waiting on the real fs_poll interval.
  -- ---------------------------------------------------------------------
  if git_available then
    local function git(args)
      local cmd = vim.list_extend({ "git", "-C", workspace }, args)
      vim.fn.system(cmd)
      return vim.v.shell_error == 0
    end
    local notes_path = workspace .. "/NOTES.md"
    local nf = assert(io.open(notes_path, "w"))
    nf:write("e2e notes\n")
    nf:close()
    git({ "add", "-A" })
    git({ "commit", "-q", "-m", "second commit" })
    session._signals.git._on_head_change()
  end

  -- ---------------------------------------------------------------------
  -- 9. session.heartbeat: force a deterministic tick (no real timer wait).
  -- ---------------------------------------------------------------------
  session._signals.heartbeat._tick()

  -- ---------------------------------------------------------------------
  -- 10. Seal. Checkpoint scheduling happened automatically during steps
  --     5-9 (checkpoint_interval=3); seal() drains any pending checkpoint
  --     before flushing, so it lands in the sealed .slog.meta regardless.
  -- ---------------------------------------------------------------------
  local seal_result = session.seal({ now = function() return "2026-05-19T14:30:00.000Z" end })
  if seal_result.kind ~= "ok" then
    error("seal failed: " .. vim.inspect(seal_result))
  end

  -- ---------------------------------------------------------------------
  -- 11. Read back the .slog (still on disk -- seal() doesn't delete it)
  --     for the distinct set of event kinds, for the caller to print.
  -- ---------------------------------------------------------------------
  local slog_lines = vim.fn.readfile(session.slog_path, "b")
  local slog_text = table.concat(slog_lines, "\n")
  local parsed = core_ndjson.parse_entries(slog_text)
  if not parsed.ok then
    error("failed to parse sealed .slog for kind reporting: " .. vim.inspect(parsed))
  end
  local kinds_seen = {}
  local kinds_order = {}
  for _, e in ipairs(parsed.value) do
    if not kinds_seen[e.kind] then
      kinds_seen[e.kind] = true
      table.insert(kinds_order, e.kind)
    end
  end

  session.stop("e2e-complete")

  -- ---------------------------------------------------------------------
  -- 12. Copy the produced bundle to a stable name in PROVNVIM_E2E_OUT.
  -- ---------------------------------------------------------------------
  local uv = vim.uv or vim.loop
  local src_fd = assert(uv.fs_open(seal_result.bundle_path, "r", 438))
  local st = assert(uv.fs_fstat(src_fd))
  local bytes = assert(uv.fs_read(src_fd, st.size, 0))
  uv.fs_close(src_fd)

  local dest_path = out_dir .. "/full-signals-bundle.zip"
  local dest_fd = assert(uv.fs_open(dest_path, "w", 420))
  assert(uv.fs_write(dest_fd, bytes, 0))
  uv.fs_close(dest_fd)

  print("E2E_FULL_BUNDLE_OK " .. dest_path)
  print("E2E_FULL_BUNDLE_KINDS " .. table.concat(kinds_order, " "))
end)

if not ok then
  fail(err)
end

os.exit(0)
