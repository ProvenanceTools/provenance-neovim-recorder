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
  --    the committed dev fixture (tests/conformance/fixtures/manifest.json)
  --    whose inner `manifest` object verifies against the embedded course
  --    public key (provenance.course_public_key.COURSE_PUBLIC_KEY_HEX).
  -- ---------------------------------------------------------------------
  -- `<sfile>` is a Vimscript-source concept and does not resolve reliably
  -- for a script loaded via `nvim -l`; use debug.getinfo on this running
  -- chunk instead (source is "@/abs/path/to/produce_bundle.lua").
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

  -- Verify activation the same way the real plugin's activation gate would
  -- (fail loudly here rather than silently starting an unverified session —
  -- if this ever fails it means the fixture/course key drifted).
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
  local rf = assert(io.open(reviewed_abs, "w"))
  rf:write("print('hello world')\n")
  rf:close()

  -- ---------------------------------------------------------------------
  -- 3. Start a real recording session against the activated workspace.
  -- ---------------------------------------------------------------------
  local session = recording_session.start({
    workspace = workspace,
    provenance_dir = provenance_dir,
    manifest = manifest,
    clock = core_clock.system(),
  })

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
  -- 5. Seal. The saved on-disk bytes (from step 4's :write) are what seal
  --    reads for submission_files, so they match what was recorded.
  -- ---------------------------------------------------------------------
  local seal_result = session.seal({ now = function() return "2026-05-19T14:30:00.000Z" end })
  if seal_result.kind ~= "ok" then
    error("seal failed: " .. vim.inspect(seal_result))
  end

  session.stop("e2e-complete")

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
