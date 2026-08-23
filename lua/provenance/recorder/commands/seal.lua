--- Bundle seal command (Plan 4). Port of the monorepo's
--- `packages/recorder/src/commands/seal.ts` (`sealBundle`) — see that file
--- for the authoritative step-by-step; this module mirrors its logic and
--- design notes exactly, substituting `vim.uv` for node:fs and
--- `core`/`recorder.io` modules for `@provenance/log-core`.
---
--- Produces:
---   <provenance_dir>/manifest.json  — BundleManifest 1.1 (atomic write, the
---     exact canonical JSON that was signed — never re-serialized)
---   <provenance_dir>/manifest.sig   — hex ed25519 signature over that JSON
---   <output_dir>/<assignment_id>-bundle-<ts>.zip — ZIP of provenance_dir's
---     contents (slog + meta + manifest + sig) plus the reviewed files'
---     raw bytes at their workspace-relative paths.
---
--- Design notes (mirrored from seal.ts):
---   - NEVER aborts on a broken or unparseable chain. Warnings accumulate
---     instead and the bundle is always sealed — a student must be able to
---     submit even after a recording glitch. The analyzer detects tampering
---     independently via its own chain check.
---   - meta files are optional/defensive: if a `.slog.meta` can't be read,
---     its hash falls back to sha256("") rather than aborting.
---   - Missing reviewed files are recorded in submission_files with
---     status "missing" (sha256 = null) but are not added to the zip. A
---     reviewed file that exists but can't be READ (a directory, a
---     permission error, a FIFO, ...) is a different fact — it is DROPPED
---     entirely (neither submission_files nor the zip) and reported via
---     warnings.unreadable_in_scope_file, never recorded as "missing".
---   - manifest.json / manifest.sig are atomic writes (write-temp-then-
---     rename via recorder.io.atomic_write) so a signed, integrity-critical
---     file is never observed half-written.
local core_ndjson = require("provenance.core.ndjson")
local core_chain_validator = require("provenance.core.chain_validator")
local core_sha256 = require("provenance.core.sha256")
local core_bundle = require("provenance.core.bundle")
local core_json = require("provenance.core.json")
local rolling_manifest = require("provenance.core.rolling_manifest")
local atomic_write = require("provenance.recorder.io.atomic_write")
local zip_writer = require("provenance.recorder.io.zip_writer")

local M = {}

-- ---------------------------------------------------------------------------
-- seal_dropped_artifacts
-- ---------------------------------------------------------------------------

--- True iff `seal_bundle`'s `warnings` reports that ANYTHING was left out of
--- the bundle: an orphaned/empty session artifact dropped so the bundle stays
--- openable, or a workspace source file that could not be read at seal time.
--- Port of the monorepo's `sealDroppedArtifacts` (`packages/recorder/src/commands/seal.ts`).
---
--- A dropped artifact must never read as "nothing was wrong" — see this
--- module's own warnings, and `init.lua`'s `notify_seal_result`, which gates a
--- SEPARATE "some files could not be included" notice on this predicate. Kept
--- deliberately independent of `chain_broken`: that flag means the recording
--- itself looks tampered, which is a different (and worse) fact than "a file
--- was left out of the evidence bundle" — the two must never share one notice.
---
--- Does NOT include `unreadable_session` or `chain_broken`: those describe a
--- problem WITH a packed session's contents, not a session/file being dropped
--- from the bundle outright, and `chain_broken` already gets its own notice.
---
--- provnvim has no out-of-workspace or duplicate-drop case yet (those arrive
--- with a later task, alongside `unreadableScopeDirectory` /
--- `duplicateEntryDropped` on the monorepo side) — only the five flags below
--- exist here today.
--- @param warnings table  `seal_bundle`'s `result.warnings`
--- @return boolean
function M.seal_dropped_artifacts(warnings)
  if warnings == nil then
    return false
  end
  return warnings.orphaned_meta == true
    or warnings.orphaned_slog == true
    or warnings.empty_session == true
    or warnings.orphaned_rolling_seal == true
    or warnings.unreadable_in_scope_file == true
end

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

--- Read a whole file's raw bytes via vim.uv. Never throws. Discriminates
--- WHY the read failed rather than collapsing every failure to a bare nil:
--- a caller may turn a failure into a `status = "missing"` submission-files
--- record, which is an AFFIRMATIVE claim about a student ("this file was
--- named and is not there") rendered into academic-integrity proceedings.
--- Only ENOENT — the file genuinely does not exist — actually means that.
--- Everything else (a directory, a permission error, a FIFO, a symlink
--- loop, ...) is `"unreadable"`: the file's existence is either known-true
--- or simply undetermined, and `"missing"` would be a false claim.
---
--- Only a REGULAR file is read: `fs_stat` (which FOLLOWS symlinks, so an
--- ordinary in-workspace symlink to a real file still reads normally — do
--- NOT switch this to `fs_lstat`, that would misreport a legitimate case)
--- runs BEFORE `fs_open`, because opening a FIFO with no writer BLOCKS THE
--- ENTIRE NEOVIM PROCESS FOREVER with no timeout anywhere in this call
--- stack, whereas `fs_stat` never blocks on one. This also gives a
--- directory (a manifest typo naming `src` instead of `src/`) a clean home
--- before `fs_open`: `fs_open` SUCCEEDS on a directory on macOS, and the
--- failure would otherwise land at `fs_read` as EISDIR. Verified
--- empirically in this repo (see the task report this fix shipped with):
--- `uv.fs_stat` / `uv.fs_open` return `nil, message, name` on failure, where
--- `name` is the bare errno string ("ENOENT", "EACCES", ...); `fs_stat`
--- follows symlinks and reports a FIFO's type instantly without opening it.
---
--- Duplicated byte-for-byte in `io/rolling_seal_writer.lua`'s own copy of
--- this helper rather than factored into a shared module — each module
--- already carries its own private `read_file_bytes`, and introducing a new
--- shared file here is exactly the kind of dependency this fix is trying to
--- avoid picking up (see this fix's commit message / task notes).
--- @param path string
--- @return string|nil, string|nil  bytes on success (nil second value);
---   else nil, "missing" (ENOENT only — from the stat, the open, or a race
---   between them) | "unreadable" (any other failure, including a
---   non-regular file)
local function read_file_bytes(path)
  local uv = vim.uv or vim.loop

  local st, _stat_msg, stat_code = uv.fs_stat(path)
  if st == nil then
    if stat_code == "ENOENT" then
      return nil, "missing"
    end
    return nil, "unreadable"
  end
  if st.type ~= "file" then
    return nil, "unreadable"
  end

  local fd, _open_msg, open_code = uv.fs_open(path, "r", 438) -- 438 = 0o666
  if fd == nil then
    if open_code == "ENOENT" then
      return nil, "missing"
    end
    return nil, "unreadable"
  end
  local ok, data = pcall(function()
    local fst = uv.fs_fstat(fd)
    if not fst then
      error("fstat failed")
    end
    local chunk = uv.fs_read(fd, fst.size, 0)
    if chunk == nil then
      error("read failed")
    end
    return chunk
  end)
  uv.fs_close(fd) -- always close, on both the success and error paths
  if not ok then
    return nil, "unreadable"
  end
  return data, nil
end

--- Byte size of a file via vim.uv.fs_stat, or nil if it cannot be stat'd.
--- @param path string
--- @return number|nil
local function file_size(path)
  local uv = vim.uv or vim.loop
  local st = uv.fs_stat(path)
  if not st then
    return nil
  end
  return st.size
end

--- List entry names of a directory via vim.uv.fs_scandir. Never throws.
--- @param path string
--- @return table|nil  list of names, or nil if the directory can't be scanned
local function list_dir_names(path)
  local uv = vim.uv or vim.loop
  local handle = uv.fs_scandir(path)
  if not handle then
    return nil
  end
  local names = {}
  while true do
    local name = uv.fs_scandir_next(handle)
    if name == nil then
      break
    end
    names[#names + 1] = name
  end
  return names
end

--- sha256 of a file's bytes, or sha256("") as a defensive fallback if the
--- file doesn't exist / can't be read (mirrors seal.ts's sha256OfFile).
--- @param path string
--- @return string  64-char lowercase hex
local function sha256_of_file(path)
  local bytes = read_file_bytes(path)
  if bytes == nil then
    return core_sha256.hex("")
  end
  return core_sha256.hex(bytes)
end

-- ---------------------------------------------------------------------------
-- seal_bundle
-- ---------------------------------------------------------------------------

--- @param opts table {
---   workspace, provenance_dir, assignment_id, semester, files_under_review,
---   session_privkey, session_pubkey_hex, compute_extension_hash?, now,
---   output_dir?,
--- }
--- @return table
---   { kind = "ok", bundle_path, manifest_sha256,
---     warnings = {chain_broken, unreadable_session, orphaned_meta, orphaned_slog,
---                 empty_session, orphaned_rolling_seal, unreadable_in_scope_file} }
---   | { kind = "no_sessions" }
---   | { kind = "write_error", message = string }
function M.seal_bundle(opts)
  local workspace = opts.workspace
  local provenance_dir = opts.provenance_dir
  local assignment_id = opts.assignment_id
  local semester = opts.semester
  local files_under_review = opts.files_under_review or {}
  local session_privkey = opts.session_privkey
  local compute_extension_hash = opts.compute_extension_hash
    or require("provenance.recorder.commands.extension_hash").compute_installed
  local now = opts.now
  local output_dir = opts.output_dir or workspace

  -- Step 1: list .slog files (excludes .slog.meta — that pattern doesn't
  -- match the anchored %.slog$ suffix) and PAIR them with their .slog.meta.
  local names = list_dir_names(provenance_dir)
  if not names then
    return { kind = "no_sessions" }
  end

  local warnings = {
    chain_broken = false,
    unreadable_session = false,
    orphaned_meta = false,
    orphaned_slog = false,
    empty_session = false,
    orphaned_rolling_seal = false,
    unreadable_in_scope_file = false,
  }

  -- ORPHAN GUARD. `analysis-core`'s loader pairs `session-<uuid>.slog` with
  -- `session-<uuid>.slog.meta` by filename and rejects THE WHOLE BUNDLE if
  -- either half is missing (`orphaned_meta` / `orphaned_slog`) — before a single
  -- validation check runs. So one unpaired file costs a student every session
  -- they recorded, not just that one.
  --
  -- Unpaired files are real and expected, not hypothetical:
  --   * chain_recovery quarantines a damaged `.slog` to `.corrupt-<ts>`, which
  --     the zip step excludes, and leaves the `.slog.meta` under its original
  --     name — so the salvage path itself produced an unopenable bundle.
  --   * a session that starts and never flushes (fixed at source in
  --     session_writer.open, but this stays as the backstop for any way the
  --     pair can still desynchronise — e.g. the eager create failing on a full
  --     disk).
  --
  -- The rule: an unpaired file is DROPPED from the bundle and reported in
  -- `warnings`. Never an abort — seal must always produce something submittable
  -- (a student cannot fix this at 11pm, and the analyzer detects problems from
  -- the evidence that IS there). Never silent either: the warning surfaces at
  -- the :ProvenanceSeal call site exactly like `chain_broken`, so a student can
  -- tell staff that a session was dropped rather than discovering it in an
  -- integrity meeting.
  --
  -- An orphaned `.slog` is dropped from the MANIFEST as well as the zip. Those
  -- two must agree: a manifest naming a session whose file is absent is just a
  -- different way to make the bundle unopenable.
  local present = {}
  for _, name in ipairs(names) do
    present[name] = true
  end

  -- A CONTENTLESS `.slog` is dropped too, with its meta. Since
  -- session_writer.open() creates the file eagerly, a session that starts and
  -- never flushes now leaves a well-paired but EMPTY `.slog` — and the loader
  -- rejects the whole bundle for that as surely as for an orphan
  -- (`first_event_not_session_start`, actualKind "none"). Zero bytes means the
  -- session recorded literally nothing, so dropping it discards no evidence;
  -- keeping it would discard all of it.
  local slog_names = {}
  for _, name in ipairs(names) do
    if name:match("%.slog$") then
      if not present[name .. ".meta"] then
        warnings.orphaned_slog = true
      elseif (file_size(provenance_dir .. "/" .. name) or 0) == 0 then
        warnings.empty_session = true
      else
        slog_names[#slog_names + 1] = name
      end
    end
  end

  -- A `.slog.meta` whose `.slog` is absent (or was quarantined away).
  local packable = {}
  for _, name in ipairs(slog_names) do
    packable[name] = true
    packable[name .. ".meta"] = true
  end
  for _, name in ipairs(names) do
    if name:match("%.slog%.meta$") and not packable[name] then
      warnings.orphaned_meta = true
    end
  end

  if #slog_names == 0 then
    return { kind = "no_sessions" }
  end
  table.sort(slog_names)

  -- Step 2: parse + validate each .slog. Warnings accumulate; never abort.
  local session_entries = {}

  -- LOGICAL session ids of the sessions this bundle will actually carry, keyed
  -- for the rolling-seal guard in step 9. TWO-UUID RULE: this is
  -- `session.start.data.session_id`, NOT the `.slog` filename uuid — a rolling
  -- manifest is named `manifest-<LOGICAL id>.json` and the analyzer reconciles
  -- it against the ids it parses out of session.start, so the filename uuid is
  -- the wrong key and would drop every rolling seal.
  local packed_session_ids = {}

  for _, filename in ipairs(slog_names) do
    local slog_path = provenance_dir .. "/" .. filename
    local meta_path = slog_path .. ".meta"

    local slog_text = read_file_bytes(slog_path)
    if slog_text == nil then
      return { kind = "write_error", message = "Failed to read " .. filename }
    end

    local parsed = core_ndjson.parse_entries(slog_text)
    if not parsed.ok then
      -- Malformed slog — accumulate warning, still include file hashes.
      warnings.unreadable_session = true
      session_entries[#session_entries + 1] = {
        session_id = core_json.NULL,
        prev_session_id = core_json.NULL,
        slog_sha256 = sha256_of_file(slog_path),
        meta_sha256 = sha256_of_file(meta_path),
      }
    else
      local entries = parsed.value

      -- Validate the chain — set warning but do NOT abort.
      local chain = core_chain_validator.validate_chain(entries)
      if not chain.ok then
        warnings.chain_broken = true
      end

      -- Extract session ids from entries[1]. Missing/malformed session.start
      -- → unreadable session, use null ids.
      local session_id = core_json.NULL
      local prev_session_id = core_json.NULL
      local first = entries[1]
      if first ~= nil and first.kind == "session.start" and type(first.data.session_id) == "string" then
        session_id = first.data.session_id
        if type(first.data.prev_session_id) == "string" then
          prev_session_id = first.data.prev_session_id
        else
          prev_session_id = core_json.NULL
        end
      else
        warnings.unreadable_session = true
      end

      if type(session_id) == "string" then
        packed_session_ids[session_id] = true
      end

      session_entries[#session_entries + 1] = {
        session_id = session_id,
        prev_session_id = prev_session_id,
        slog_sha256 = sha256_of_file(slog_path),
        meta_sha256 = sha256_of_file(meta_path),
      }
    end
  end

  -- Step 3: read reviewed files (workspace-relative; resolved against workspace).
  --
  -- `read_file_bytes` distinguishes WHY a reviewed file couldn't be read.
  -- "missing" (ENOENT — the file genuinely is not there) is the ONE case
  -- recorded as status = "missing"; it's an affirmative claim about the
  -- student, so it must never be minted for a file that's actually sitting
  -- on disk. "unreadable" (a directory, a permission error, a FIFO, ...) is
  -- DROPPED entirely — it appears in neither submission_files nor the zip,
  -- and is never conflated with "missing" — and reported via
  -- warnings.unreadable_in_scope_file so staff can tell the two facts apart
  -- (a silent drop here is what took four fix rounds to close on the
  -- monorepo's classic seal).
  local reviewed_files = {}
  for _, rel in ipairs(files_under_review) do
    local abs = workspace .. "/" .. rel
    local bytes, err = read_file_bytes(abs)
    if bytes ~= nil then
      reviewed_files[#reviewed_files + 1] = {
        path = rel,
        status = "present",
        sha256 = core_sha256.hex(bytes),
        bytes = bytes,
      }
    elseif err == "missing" then
      reviewed_files[#reviewed_files + 1] = { path = rel, status = "missing", sha256 = core_json.NULL }
    else
      warnings.unreadable_in_scope_file = true
    end
  end

  local submission_files = {}
  for i, f in ipairs(reviewed_files) do
    submission_files[i] = { path = f.path, status = f.status, sha256 = f.sha256 }
  end

  -- Step 4: extension hash.
  local ext_ok, extension_hash = pcall(compute_extension_hash)
  if not ext_ok then
    return { kind = "write_error", message = "Failed to compute extension hash: " .. tostring(extension_hash) }
  end

  -- Step 5: build BundleManifest (format_version 1.1).
  local manifest_value = core_bundle.build({
    format_version = "1.1",
    assignment_id = assignment_id,
    semester = semester,
    extension_hash = extension_hash,
    sessions = session_entries,
    submission_files = submission_files,
  })

  -- Step 6: canonicalize + sign.
  local sign_ok, signed = pcall(core_bundle.sign, manifest_value, session_privkey)
  if not sign_ok then
    return { kind = "write_error", message = "Failed to sign manifest: " .. tostring(signed) }
  end

  -- Step 7: atomic-write manifest.json (exact canonical JSON, never
  -- re-serialized) and manifest.sig.
  local manifest_path = provenance_dir .. "/manifest.json"
  local sig_path = provenance_dir .. "/manifest.sig"
  local write_ok, write_err = pcall(function()
    atomic_write.atomic_write_file(manifest_path, signed.canonical_json)
    atomic_write.atomic_write_file(sig_path, signed.signature_hex)
  end)
  if not write_ok then
    return { kind = "write_error", message = "Failed to write manifest/sig: " .. tostring(write_err) }
  end

  local manifest_sha256 = core_sha256.hex(signed.canonical_json)

  -- Step 9: re-scan provenance_dir (now includes manifest.json/.sig) and
  -- build the zip entry list, skipping quarantine (.corrupt-) and temp
  -- (.tmp) files.
  local dir_names = list_dir_names(provenance_dir)
  if not dir_names then
    return { kind = "write_error", message = "Failed to read provenance dir: " .. provenance_dir }
  end

  -- ROLLING-SEAL HALF OF THE ORPHAN GUARD.
  --
  -- The rolling seal (`manifest-<session_id>.json` + `.sig`) is a THIRD
  -- per-session artifact, written eagerly at session start — before the `.slog`
  -- has been flushed even once — and rewritten at every checkpoint and at
  -- teardown. It therefore outlives any reason step 1 has for dropping a
  -- session, and the guard above knows nothing about it.
  --
  -- `analysis-core`'s `reconcileRollingSealsWithSessions` reports
  -- `no_session_log` for a seal whose session is not in the bundle — the seal
  -- names a recording that is not here, and its signature can never be checked,
  -- because the verifying pubkey lives in that session's own session.start. That
  -- defect fails check 1 (`manifest_sig`) for THE WHOLE BUNDLE, so one stale
  -- manifest costs a student every session they recorded — exactly the blast
  -- radius the `.slog`/`.slog.meta` guard exists to prevent.
  --
  -- This is not hypothetical; it is what `scripts/e2e/run_e2e.sh` hits. Two
  -- sessions start against one root (the plugin's BufEnter activation opens a
  -- second one). The second emits `session.start` into its buffer, takes its
  -- session-start roll, and is torn down before it ever flushes, leaving a
  -- zero-byte `.slog` that step 1 correctly drops as `empty_session` — and a
  -- `manifest-<its id>.json` that used to be packed anyway.
  --
  -- The rule matches step 1's: DROP from the zip, report in `warnings`, never
  -- abort. And drop only from the ZIP — the files stay on disk untouched, so a
  -- git-submitted `.provenance/` keeps the seal that write point 1 exists to
  -- provide, and a shared repo keeps a partner's evidence. (A partner's session
  -- is packed WITH its seal: their `.slog`, `.slog.meta` and
  -- `manifest-<id>.json` all pair up, so nothing of theirs is dropped.)
  --
  -- Dropping a rolling seal cannot itself create a finding: `unsealed_session`
  -- is only reported for a bundle with NO classic seal, and every bundle this
  -- function produces carries `manifest.json` — which covers every session it
  -- packs. So inside a classic bundle a rolling seal is redundant, and a stale
  -- one is pure liability.
  local function rolling_seal_is_orphaned(filename)
    local parsed = rolling_manifest.parse_filename(filename)
    -- nil for `manifest.json` / `manifest.sig` (the CLASSIC seal, always packed)
    -- and for `.tmp` staging names.
    if parsed == nil then
      return false
    end
    return not packed_session_ids[parsed.session_id]
  end

  local zip_entries = {}
  for _, filename in ipairs(dir_names) do
    local is_session_file = filename:match("%.slog$") ~= nil or filename:match("%.slog%.meta$") ~= nil
    -- Session files must be PAIRED to be packed (see the orphan guard in step
    -- 1). Everything else that is not quarantine (.corrupt-) or a temp (.tmp)
    -- file is packed as before: manifest.json, manifest.sig, and anything a
    -- future step drops in here.
    local packable_here = (not is_session_file) or packable[filename]
    if packable_here and rolling_seal_is_orphaned(filename) then
      -- Both halves go together: a `.sig` without its `.json` vouches for
      -- nothing, and a `.json` without its `.sig` is an unsigned claim
      -- (`missing_sig`). `parse_filename` matches each half independently, so
      -- each is dropped on its own pass and the pair stays consistent.
      warnings.orphaned_rolling_seal = true
      packable_here = false
    end
    if packable_here
      and not filename:find(".corrupt-", 1, true)
      and not filename:match("%.tmp$")
    then
      local bytes = read_file_bytes(provenance_dir .. "/" .. filename)
      if bytes ~= nil then
        zip_entries[#zip_entries + 1] = { name = filename, data = bytes }
      end
      -- File disappeared between scandir and read — skip it (mirrors seal.ts).
    end
  end
  table.sort(zip_entries, function(a, b)
    return a.name < b.name
  end)

  -- Add submitted file bytes at the zip root (mirrors the workspace layout).
  -- Missing files are recorded in the manifest but not added to the zip.
  for _, f in ipairs(reviewed_files) do
    if f.status == "present" then
      zip_entries[#zip_entries + 1] = { name = f.path, data = f.bytes }
    end
  end

  -- Step 10: write the ZIP.
  local ts = now():gsub(":", "-")
  local zip_filename = assignment_id .. "-bundle-" .. ts .. ".zip"
  local bundle_path = output_dir .. "/" .. zip_filename

  local zip_ok, zip_err = pcall(zip_writer.write, bundle_path, zip_entries)
  if not zip_ok then
    return { kind = "write_error", message = "Failed to write bundle ZIP: " .. tostring(zip_err) }
  end

  return { kind = "ok", bundle_path = bundle_path, manifest_sha256 = manifest_sha256, warnings = warnings }
end

return M
