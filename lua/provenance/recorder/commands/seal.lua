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
---     status "missing" (sha256 = null) but are not added to the zip.
---   - manifest.json / manifest.sig are atomic writes (write-temp-then-
---     rename via recorder.io.atomic_write) so a signed, integrity-critical
---     file is never observed half-written.
local core_ndjson = require("provenance.core.ndjson")
local core_chain_validator = require("provenance.core.chain_validator")
local core_sha256 = require("provenance.core.sha256")
local core_bundle = require("provenance.core.bundle")
local core_json = require("provenance.core.json")
local atomic_write = require("provenance.recorder.io.atomic_write")
local zip_writer = require("provenance.recorder.io.zip_writer")

local M = {}

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

--- Read a whole file's raw bytes via vim.uv. Never throws.
--- @param path string
--- @return string|nil  file bytes, or nil if the file can't be read
local function read_file_bytes(path)
  local uv = vim.uv or vim.loop
  local fd = uv.fs_open(path, "r", 438) -- 438 = 0o666
  if not fd then
    return nil
  end
  local ok, data = pcall(function()
    local st = uv.fs_fstat(fd)
    if not st then
      error("fstat failed")
    end
    local chunk = uv.fs_read(fd, st.size, 0)
    if chunk == nil then
      error("read failed")
    end
    return chunk
  end)
  uv.fs_close(fd) -- always close, on both the success and error paths
  if not ok then
    return nil
  end
  return data
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
---   { kind = "ok", bundle_path, manifest_sha256, warnings = {chain_broken, unreadable_session} }
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
    or require("provenance.recorder.commands.extension_hash").compute
  local now = opts.now
  local output_dir = opts.output_dir or workspace

  -- Step 1: list .slog files (excludes .slog.meta — that pattern doesn't
  -- match the anchored %.slog$ suffix).
  local names = list_dir_names(provenance_dir)
  if not names then
    return { kind = "no_sessions" }
  end

  local slog_names = {}
  for _, name in ipairs(names) do
    if name:match("%.slog$") then
      slog_names[#slog_names + 1] = name
    end
  end
  if #slog_names == 0 then
    return { kind = "no_sessions" }
  end
  table.sort(slog_names)

  -- Step 2: parse + validate each .slog. Warnings accumulate; never abort.
  local warnings = { chain_broken = false, unreadable_session = false }
  local session_entries = {}

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

      session_entries[#session_entries + 1] = {
        session_id = session_id,
        prev_session_id = prev_session_id,
        slog_sha256 = sha256_of_file(slog_path),
        meta_sha256 = sha256_of_file(meta_path),
      }
    end
  end

  -- Step 3: read reviewed files (workspace-relative; resolved against workspace).
  local reviewed_files = {}
  for _, rel in ipairs(files_under_review) do
    local abs = workspace .. "/" .. rel
    local bytes = read_file_bytes(abs)
    if bytes ~= nil then
      reviewed_files[#reviewed_files + 1] = {
        path = rel,
        status = "present",
        sha256 = core_sha256.hex(bytes),
        bytes = bytes,
      }
    else
      reviewed_files[#reviewed_files + 1] = { path = rel, status = "missing", sha256 = core_json.NULL }
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

  local zip_entries = {}
  for _, filename in ipairs(dir_names) do
    if not filename:find(".corrupt-", 1, true) and not filename:match("%.tmp$") then
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
