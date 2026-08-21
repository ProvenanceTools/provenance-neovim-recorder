--- Plan 4 Task 10 (SUCCESS CRITERION): headless driver that produces a real
--- sealed submission bundle by exercising the live recording_session wiring
--- exactly the way a student's editor session would — activation manifest on
--- disk, a real doc.open/doc.change/doc.save cycle against a reviewed file,
--- then seal(). The resulting `.zip` is copied to a stable name under
--- $PROVNVIM_E2E_OUT so scripts/verify-bundle-with-analyzer.mjs (run in the
--- real Provenance monorepo) can load it via analysis-core's loadBundle +
--- runValidation.
---
--- NOT a plenary spec — this is a throwaway CLI-style script, run via:
---   nvim --headless -u tests/minimal_init.lua -l scripts/e2e/produce_bundle.lua
--- (tests/minimal_init.lua bootstraps the runtimepath, so
--- require("provenance...") resolves the same way it does under `make test`.)
---
--- On success: prints "E2E_BUNDLE_OK <path>" and exits 0.
--- On any error: prints the error and os.exit(1).

local function fail(msg)
  io.stderr:write("E2E_BUNDLE_FAIL: " .. tostring(msg) .. "\n")
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

  local core_manifest = require("provenance.core.manifest")
  local activation = require("provenance.recorder.activation")
  local core_clock = require("provenance.core.clock")
  local recording_session = require("provenance.recorder.session.recording_session")

  -- ---------------------------------------------------------------------
  -- 1. Temp workspace with a valid signed .provenance-manifest, built from
  --    the committed 1.x gate fixture
  --    (tests/recorder/fixtures/legacy-manifest-v1.json), signed with the
  --    recorder's own embedded master key. Activation below passes NO pubkey
  --    override, so this exercises the REAL embedded LEGACY_COURSE_PUBLIC_KEY_HEX
  --    -- the grandfathered 1.x path, end to end.
  --
  --    Deliberately NOT tests/conformance/fixtures/manifest.json: that file is a
  --    generated conformance vector signed with the vector generator's key, and
  --    it must stay byte-identical to provjet's copy. It used to serve both
  --    roles, and regenerating the vector silently broke this gate.
  -- ---------------------------------------------------------------------
  -- `<sfile>` is a Vimscript-source concept and does not resolve reliably
  -- for a script loaded via `nvim -l`; use debug.getinfo on this running
  -- chunk instead (source is "@/abs/path/to/produce_bundle.lua").
  local this_file = debug.getinfo(1, "S").source:sub(2)
  local repo_root = vim.fn.fnamemodify(vim.fn.resolve(vim.fn.fnamemodify(this_file, ":p")), ":h:h:h")
  local fixture_path = repo_root .. "/tests/recorder/fixtures/legacy-manifest-v1.json"
  local manifest_text = table.concat(vim.fn.readfile(fixture_path, "b"), "\n")
  local fixture_manifest = vim.json.decode(manifest_text)
  if type(fixture_manifest) ~= "table" or type(fixture_manifest.sig) ~= "string" then
    error("1.x gate fixture legacy-manifest-v1.json is not a signed manifest object")
  end

  local workspace = vim.fs.normalize(vim.fn.tempname())
  vim.fn.mkdir(workspace, "p")

  local manifest_file_path = workspace .. "/.provenance-manifest"
  local mf = assert(io.open(manifest_file_path, "w"))
  mf:write(manifest_text)
  mf:close()

  local provenance_dir = workspace .. "/.provenance"
  vim.fn.mkdir(provenance_dir, "p")

  -- Verify activation the same way the real plugin's activation gate would
  -- (fail loudly here rather than silently starting an unverified session —
  -- if this ever fails it means the fixture/course key drifted).
  -- No pubkey override: this is the grandfather gate, so it must go through the
  -- embedded LEGACY_COURSE_PUBLIC_KEY_HEX exactly as a student's editor does.
  local activated = activation.load_and_verify(workspace)
  if activated.status ~= "active" then
    error("dev fixture manifest failed activation: " .. vim.inspect(activated))
  end
  local manifest = activated.manifest

  -- ---------------------------------------------------------------------
  -- 2. A reviewed file listed in files_under_review.
  -- ---------------------------------------------------------------------
  local reviewed_rel = manifest.files_under_review[1]
  if not reviewed_rel then
    error("fixture manifest has no files_under_review entries")
  end
  local reviewed_abs = workspace .. "/" .. reviewed_rel
  vim.fn.mkdir(vim.fn.fnamemodify(reviewed_abs, ":h"), "p")

  -- Optional CRLF/dos-fileformat variant (finding-1 regression proof): the
  -- ON-DISK bytes already have \r\n line endings BEFORE nvim ever opens the
  -- file, matching the realistic scenario ("Windows default" / any
  -- CRLF-authored file) -- Neovim's `'fileformats'` autodetects fileformat
  -- =dos from this on open, exactly like the doc_wiring_spec.lua CRLF
  -- coverage. (Forcing 'fileformat' mid-session on an already-open unix
  -- buffer is a DIFFERENT, harder scenario -- a global EOL-character
  -- conversion of every line, not a line-granular edit -- and is out of
  -- scope for this fix.)
  local forced_fileformat = os.getenv("PROVNVIM_E2E_FILEFORMAT")
  local reviewed_content = "print('hello world')\n"
  if forced_fileformat == "dos" then
    reviewed_content = "print('hello world')\r\n"
  end
  local rf = assert(io.open(reviewed_abs, "w"))
  rf:write(reviewed_content)
  rf:close()

  -- ---------------------------------------------------------------------
  -- 2b. A PARTNER'S SESSION, recorded in its own workspace (Tier 4.1, peer
  --     witnessing). This stands in for the other student in a shared repo:
  --     a real recording session, real keypair, real signed chain, produced by
  --     this same recorder — just not by this student.
  --
  --     Its `.slog` + `.slog.meta` are copied into the student's
  --     `.provenance/` at step 3b, which is exactly what a `git pull` does.
  --     The student's own session then witnesses it into ITS OWN signed chain,
  --     and the real monorepo `reconcileWitnesses` must read that witness as
  --     `corroborated` — see scripts/verify-bundle-with-analyzer.mjs.
  --
  --     Sequential, not concurrent: the partner session is fully stopped before
  --     the student's starts, so nothing about two live sessions in one Neovim
  --     is being relied on.
  -- ---------------------------------------------------------------------
  --     NOTE the partner workspace deliberately gets NO `.provenance-manifest`
  --     on disk. `recording_session.start` takes the already-verified manifest
  --     TABLE, so the file is not needed — and writing one would make the
  --     plugin's own BufEnter/BufReadPost activation fire when this script
  --     `:edit`s a file there, starting a SECOND, unasked-for recorder. See the
  --     `--noplugin` note in run_e2e.sh.
  local partner_workspace = vim.fs.normalize(vim.fn.tempname())
  vim.fn.mkdir(partner_workspace, "p")
  local partner_provenance = partner_workspace .. "/.provenance"
  vim.fn.mkdir(partner_provenance, "p")
  local partner_file = partner_workspace .. "/" .. reviewed_rel
  vim.fn.mkdir(vim.fn.fnamemodify(partner_file, ":h"), "p")
  do
    local pf = assert(io.open(partner_file, "w"))
    pf:write("print('partner')\n")
    pf:close()
  end

  local partner_session = recording_session.start({
    workspace = partner_workspace,
    provenance_dir = partner_provenance,
    manifest = manifest,
    clock = core_clock.system(),
  })
  vim.cmd("edit " .. vim.fn.fnameescape(partner_file))
  local partner_buf = vim.api.nvim_get_current_buf()
  vim.api.nvim_buf_set_lines(partner_buf, 1, 1, false, { "print('partner edit')" })
  vim.cmd("write")
  partner_session.stop("partner-complete")
  pcall(vim.cmd, "bwipeout! " .. partner_buf)

  local partner_slog = partner_session.slog_path
  local partner_meta = partner_session.meta_path
  if vim.fn.filereadable(partner_slog) ~= 1 then
    error("partner session produced no .slog at " .. partner_slog)
  end

  -- ---------------------------------------------------------------------
  -- 3. Start a real recording session against the activated workspace.
  --
  --    `checkpoint_interval = 2` so the peer-witness drain — which runs on the
  --    checkpoint cadence — actually fires within the handful of entries this
  --    script produces, rather than only at stop() after the seal.
  -- ---------------------------------------------------------------------
  local session = recording_session.start({
    workspace = workspace,
    provenance_dir = provenance_dir,
    manifest = manifest,
    clock = core_clock.system(),
    checkpoint_interval = 2,
  })

  -- ---------------------------------------------------------------------
  -- 3b. `git pull`: the partner's log lands in the student's `.provenance/`.
  --     Copied, never moved — the partner's own tree is left untouched, which
  --     is the same rule the watcher itself obeys.
  -- ---------------------------------------------------------------------
  local function copy_file(src, dest)
    local text = table.concat(vim.fn.readfile(src, "b"), "\n")
    local f = assert(io.open(dest, "w"))
    f:write(text)
    f:close()
  end
  local pulled_slog = provenance_dir .. "/" .. vim.fn.fnamemodify(partner_slog, ":t")
  copy_file(partner_slog, pulled_slog)
  copy_file(partner_meta, provenance_dir .. "/" .. vim.fn.fnamemodify(partner_meta, ":t"))

  -- ---------------------------------------------------------------------
  -- 4. Drive doc.open/doc.change/doc.save through the live wiring: open the
  --    reviewed file, mutate it, save it. Catch-up in recording_session's
  --    doc-wiring attach only covers buffers already open at attach() time,
  --    so :edit here (after start()) fires BufReadPost -> doc.open live.
  -- ---------------------------------------------------------------------
  vim.cmd("edit " .. vim.fn.fnameescape(reviewed_abs))
  local buf = vim.api.nvim_get_current_buf()
  vim.api.nvim_buf_set_lines(buf, 1, 1, false, { "print('recorded by provnvim e2e')" })
  vim.cmd("write")

  -- ---------------------------------------------------------------------
  -- 4b. Wait for the peer-witness drain to land in the .slog. The checkpoint
  --     scheduler defers via vim.schedule, so the observation appears a tick
  --     or two after the edits above trip the cadence. A few more edits keep
  --     the cadence firing while we wait, and the writer flushes on its own
  --     timer.
  --
  --     Polling the FILE, not an in-memory counter, because what the analyzer
  --     will read is the bytes on disk.
  -- ---------------------------------------------------------------------
  local function slog_has_witness()
    if vim.fn.filereadable(session.slog_path) ~= 1 then
      return false
    end
    local text = table.concat(vim.fn.readfile(session.slog_path, "b"), "\n")
    return text:find("peer.observed", 1, true) ~= nil
  end

  local witnessed = vim.wait(10000, function()
    if slog_has_witness() then
      return true
    end
    local n = vim.api.nvim_buf_line_count(buf)
    vim.api.nvim_buf_set_lines(buf, n, n, false, { "# keep the cadence turning" })
    return false
  end, 100)

  if not witnessed then
    error("no peer.observed reached the .slog: the peer-witness drain did not run")
  end
  vim.cmd("write")

  -- ---------------------------------------------------------------------
  -- 5. Seal. The saved on-disk bytes (from step 4's :write) are what seal
  --    reads for submission_files, so they match what was recorded.
  -- ---------------------------------------------------------------------
  local seal_result = session.seal({ now = function() return "2026-05-19T14:30:00.000Z" end })
  if seal_result.kind ~= "ok" then
    error("seal failed: " .. vim.inspect(seal_result))
  end

  session.stop("e2e-complete")
  pcall(vim.fn.delete, partner_workspace, "rf")

  -- ---------------------------------------------------------------------
  -- 6. Copy the produced bundle to a stable name in PROVNVIM_E2E_OUT.
  -- ---------------------------------------------------------------------
  local uv = vim.uv or vim.loop
  local src_fd = assert(uv.fs_open(seal_result.bundle_path, "r", 438))
  local st = assert(uv.fs_fstat(src_fd))
  local bytes = assert(uv.fs_read(src_fd, st.size, 0))
  uv.fs_close(src_fd)

  local dest_path = out_dir .. "/e2e-bundle.zip"
  local dest_fd = assert(uv.fs_open(dest_path, "w", 420))
  assert(uv.fs_write(dest_fd, bytes, 0))
  uv.fs_close(dest_fd)

  print("E2E_BUNDLE_OK " .. dest_path)
end)

if not ok then
  fail(err)
end

os.exit(0)
