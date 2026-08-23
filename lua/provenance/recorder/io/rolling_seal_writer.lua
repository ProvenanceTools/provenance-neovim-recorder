--- The ROLLING SEAL, write side. Port of the monorepo's
--- `packages/recorder/src/io/rolling-seal-writer.ts`.
---
--- A git-submitted assignment has no seal step: the student pushes, the grader
--- clones, nothing ever runs `:ProvenanceSeal`. So the seal has to move off the
--- submission event and onto the recording itself. This module rewrites, on
--- every checkpoint,
---
---   .provenance/manifest-<session_id>.json   BundleManifest at format_version 1.2
---   .provenance/manifest-<session_id>.sig    ed25519 over the canonical JSON
---
--- so whatever is committed to git is always a valid seal of the state at that
--- moment. `core/rolling_manifest.lua` is the authoritative design; the two
--- rules this module exists to honour are:
---
---   1. The file covers EXACTLY ONE session, whose `session_id` is non-null and
---      equals the id in the filename. Filenames come from
---      `rolling_manifest.filenames()` and are never spelled by hand here, so
---      the writer and `rolling_manifest.parse_filename` cannot drift.
---   2. It is signed by THAT session's own ephemeral key — the same key whose
---      public half is recorded in `session.start`. Check 1 verifies a rolling
---      seal against exactly one pubkey, so signing with anything else fails.
---
--- ## The `final` marker
---
--- Every roll but one is taken while the log is still growing, so its digests
--- commit to a PREFIX and a reader must not treat later bytes as tampering. The
--- exception is the roll teardown takes after `session.end` is emitted and the
--- writer flushed: that log is finished, and saying so — `final = true`, inside
--- the signed payload — is what lets the reader enforce WHOLE-FILE equality and
--- catch an entry appended after the session ended.
---
--- The claim is the CALLER's to make, because only the caller knows the
--- ordering. This module just records it. Passing `final` from a checkpoint
--- would assert that a live log is finished and turn the student's next
--- keystroke into a finding, so exactly one call site sets it.
---
--- ## What this module must never touch
---
--- `manifest.json` / `manifest.sig`. Those are the CLASSIC seal, written only by
--- `commands/seal.lua`. A classic sealed bundle keeps the same 1.1 manifest, the
--- same canonical bytes and the same signature it has today. The only names this
--- module can produce come out of `rolling_manifest.filenames()`, and that
--- function cannot spell either classic name.
---
--- ## Atomicity, and the window that cannot be closed
---
--- A rolling manifest is rewritten every ~100 events into a directory that is
--- under git and gets committed. A partial write would leave a corrupt signed
--- artifact there, so both files go through `atomic_write.atomic_write_file_pair`:
--- both temps are written and fsynced, and only then are both renamed back to
--- back. See that function for the residual single-syscall window.
---
--- ## Unreadable reviewed files are dropped silently — a deliberate trade-off
---
--- A `files_under_review` entry that exists but can't be read (a directory,
--- a permission error, a FIFO, ...) is a different fact from one that's
--- genuinely absent, and must never be recorded as `status = "missing"` —
--- see `read_submission_file`'s docstring. But unlike the classic seal
--- (`commands/seal.lua`, which has a `warnings` table returned from an
--- explicit, user-invoked `:ProvenanceSeal`), this module has NO
--- user-facing channel to report a drop through: `RollingSealResult` carries
--- no warnings field, and a rolling reseal runs silently on every
--- checkpoint with no "seal now" action to attach a banner to. Rather than
--- invent a warnings channel nobody asked for, this module drops such an
--- entry from `submission_files` SILENTLY. The accepted trade-off: a
--- student won't be told mid-session that a reviewed file briefly became
--- unreadable, but a rolling seal also never mints a false `missing` for a
--- file that's actually sitting on their disk. The classic seal's
--- `warnings.unreadable_in_scope_file` is where that fact surfaces.
---
--- ## Failure is never fatal
---
--- Recording matters more than sealing. Every failure — the directory deleted by
--- a `git checkout`, a read-only checkout, a full disk — comes back as
--- `{ kind = "error" }` (CLAUDE.md: errors are values when expected). Nothing
--- here raises, so a checkpoint's sign-and-write cannot be aborted by the seal,
--- and the session records on.
local core_sha256 = require("provenance.core.sha256")
local core_bundle = require("provenance.core.bundle")
local core_json = require("provenance.core.json")
local rolling_manifest = require("provenance.core.rolling_manifest")
local atomic_write = require("provenance.recorder.io.atomic_write")

local M = {}

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

--- Read a whole file's raw bytes via vim.uv. Never raises. Discriminates WHY
--- the read failed rather than collapsing every failure to a bare nil: a
--- caller may turn a failure into a `status = "missing"` submission-files
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
--- stack — and this module runs on EVERY CHECKPOINT, so a student doing
--- `rm Main.java && mkfifo Main.java` at a tracked path would otherwise
--- wedge the whole editor without even needing a seal command to trigger
--- it. `fs_stat` never blocks on a FIFO, so gating on it first is safe.
--- This also gives a directory (a manifest typo naming `src` instead of
--- `src/`) a clean home before `fs_open`: `fs_open` SUCCEEDS on a directory
--- on macOS, and the failure would otherwise land at `fs_read` as EISDIR.
--- Verified empirically in this repo (see the task report this fix shipped
--- with): `uv.fs_stat` / `uv.fs_open` return `nil, message, name` on
--- failure, where `name` is the bare errno string ("ENOENT", "EACCES",
--- ...); `fs_stat` follows symlinks and reports a FIFO's type instantly
--- without opening it.
---
--- Duplicated byte-for-byte in `commands/seal.lua`'s own copy of this
--- helper rather than factored into a shared module — each module already
--- carries its own private `read_file_bytes`, and introducing a new shared
--- file here is exactly the kind of dependency this fix is trying to avoid
--- picking up (see this fix's commit message / task notes).
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
  uv.fs_close(fd)
  if not ok then
    return nil, "unreadable"
  end
  return data, nil
end

--- sha256 of a file's bytes, or of empty bytes when it cannot be read.
---
--- The empty-bytes fallback matches `commands/seal.lua`'s existing defensive
--- behaviour, and it is what keeps this path safe when git moves the ground: a
--- `git checkout` that removes the `.slog` mid-session yields a well-formed
--- 64-hex hash rather than an error or an unwritable manifest.
--- @param path string
--- @return string  64-char lowercase hex
local function sha256_of_file(path)
  local bytes = read_file_bytes(path)
  if bytes == nil then
    return core_sha256.hex("")
  end
  return core_sha256.hex(bytes)
end

--- Read one `files_under_review` entry's on-disk state: present, genuinely
--- missing, or unreadable.
---
--- There is no warnings channel to report a drop through here:
--- `RollingSealResult` carries no warnings field, and unlike the classic
--- seal's `:ProvenanceSeal`, a rolling reseal has no user-facing "seal now"
--- action to attach a banner to — it fires silently on every checkpoint.
--- Inventing one (e.g. threading a warnings table back through
--- `write_rolling_seal`'s return value) would be new surface nobody asked
--- for and nothing currently reads. So an "unreadable" entry (a directory,
--- a permission error, a FIFO, ...) is dropped from this rolling manifest's
--- submission_files SILENTLY (see the caller) — the accepted trade-off is
--- that a rolling seal alone won't tell a student mid-session that one of
--- their reviewed files briefly became unreadable, but it also never
--- mints a false "missing" for it. The next classic `:ProvenanceSeal` (or
--- the next rolling checkpoint, once the condition clears) is what a
--- student actually acts on, and the classic seal DOES have a warnings
--- channel (`commands/seal.lua`'s `unreadable_in_scope_file`) for exactly
--- this fact.
--- @param workspace string
--- @param rel_path string
--- @return table|nil  { path, status, sha256 } for present/missing;
---   nil to signal "drop this entry" for unreadable
local function read_submission_file(workspace, rel_path)
  local bytes, err = read_file_bytes(workspace .. "/" .. rel_path)
  if bytes ~= nil then
    return { path = rel_path, status = "present", sha256 = core_sha256.hex(bytes) }
  end
  if err == "missing" then
    return { path = rel_path, status = "missing", sha256 = core_json.NULL }
  end
  return nil
end

-- ---------------------------------------------------------------------------
-- write_rolling_seal
-- ---------------------------------------------------------------------------

--- Rewrite this session's rolling seal to reflect the state right now.
---
--- Steps:
---   1. Hash the `.slog` and `.slog.meta` as they currently stand on disk.
---   2. Hash every `files_under_review` entry; genuinely absent ones are
---      recorded `status = "missing"`, exactly as the classic seal records
---      them. Unreadable ones (a directory, a permission error, a FIFO, ...)
---      are dropped from `submission_files` entirely — see "Unreadable
---      reviewed files are dropped silently" above.
---   3. Build a 1.2 manifest covering this one session.
---   4. Canonicalize + sign with this session's own private key, via the same
---      `core_bundle.sign` the classic seal uses — so both shapes are produced
---      byte-identically.
---   5. Atomically commit `.json` + `.sig` together.
---
--- NEVER raises.
---
--- @param opts table {
---   provenance_dir: string   -- `.provenance/` for THIS session's assignment root
---   session_id: string       -- the LOGICAL id from session.start, NOT the .slog
---                            --   filename uuid (two-uuid rule). The analyzer keys
---                            --   sessions by session.start.data.session_id.
---   prev_session_id: string|nil
---   slog_path: string        -- absolute; its meta is `<slog_path>.meta`
---   workspace: string        -- assignment root, for resolving files_under_review
---   assignment_id: string
---   semester: string
---   files_under_review: table  -- from the verified course manifest
---   session_privkey: string  -- this session's 32-byte raw ed25519 seed
---   extension_hash: string   -- resolved ONCE per session by the caller; walking
---                            --   the source tree per checkpoint would be the
---                            --   pathological version of this feature
---   final: boolean|nil       -- mark this seal FINAL: the last one this session
---                            --   will ever get, so its digests commit to the
---                            --   WHOLE log rather than to a prefix.
---                            --
---                            --   Set by exactly ONE caller: the teardown roll in
---                            --   session/recording_session.lua, which runs after
---                            --   session.end has been emitted, the writer flushed
---                            --   and the pending checkpoint drained. That is the
---                            --   only moment at which the claim is true.
---                            --
---                            --   Never set it on the session-start roll or on a
---                            --   checkpoint roll. Doing so would assert that a log
---                            --   which is about to keep growing is finished, and
---                            --   the reader would then read the student's own next
---                            --   keystroke as an append past a final seal — a
---                            --   manufactured finding against someone still working.
--- }
--- @return table
---   { kind = "written", manifest_path, sig_path, canonical_json, signature_hex }
---   | { kind = "error", message = string }
function M.write_rolling_seal(opts)
  local is_final = opts.final == true

  local ok, res = pcall(function()
    -- Step 1: hashes of this session's own log files, as they are right now.
    local slog_sha256 = sha256_of_file(opts.slog_path)
    local meta_sha256 = sha256_of_file(opts.slog_path .. ".meta")

    -- Step 2: on-disk state of the reviewed files. Ordered — the manifest's
    -- submission_files order must be stable across checkpoints, otherwise the
    -- canonical bytes churn for no reason.
    local submission_files = {}
    for _, rel in ipairs(opts.files_under_review or {}) do
      -- nil means "unreadable" -- dropped silently, see read_submission_file's
      -- docstring for why this module has no warnings channel to report it
      -- through.
      local entry = read_submission_file(opts.workspace, rel)
      if entry ~= nil then
        submission_files[#submission_files + 1] = entry
      end
    end

    -- Step 3: exactly one session, non-null id, matching the filename below.
    local manifest_value = rolling_manifest.build({
      assignment_id = opts.assignment_id,
      semester = opts.semester,
      extension_hash = opts.extension_hash,
      session_id = opts.session_id,
      prev_session_id = opts.prev_session_id,
      slog_sha256 = slog_sha256,
      meta_sha256 = meta_sha256,
      submission_files = submission_files,
      -- OMITTED entirely unless final, never written as `final = false`. A
      -- non-final rolling manifest must stay byte-identical to what 1.2 emitted
      -- before this field existed: the canonical bytes are the signed message,
      -- and they are pinned by cross-language conformance vectors that two
      -- other recorder implementations verify against.
      final = is_final or nil,
    })

    -- Step 4: sign with THIS session's key.
    local signed = core_bundle.sign(manifest_value, opts.session_privkey)

    -- Step 5: commit both files. Filenames come from core/rolling_manifest so
    -- the writer and the reader's parse_filename share one definition — and so
    -- this path structurally cannot emit `manifest.json` / `manifest.sig`.
    local names = rolling_manifest.filenames(opts.session_id)
    local manifest_path = opts.provenance_dir .. "/" .. names.json
    local sig_path = opts.provenance_dir .. "/" .. names.sig

    -- Deliberately NO mkdir here. `.provenance/` is created once by
    -- recording_session.start, and if a `git checkout` has since removed it then
    -- the `.slog` this manifest claims to seal is gone too (the session writer's
    -- fd survives, but it points at an unlinked inode). Recreating the directory
    -- would leave a signed manifest sealing a log that is not there — precisely
    -- the defect the reader exists to report — and would let a straggling write
    -- resurrect a directory the student or git just deleted. Failing the seal and
    -- leaving the filesystem alone is the honest outcome.
    atomic_write.atomic_write_file_pair({
      { target_path = manifest_path, contents = signed.canonical_json },
      { target_path = sig_path, contents = signed.signature_hex },
    })

    return {
      kind = "written",
      manifest_path = manifest_path,
      sig_path = sig_path,
      canonical_json = signed.canonical_json,
      signature_hex = signed.signature_hex,
    }
  end)

  if not ok then
    return { kind = "error", message = tostring(res) }
  end
  return res
end

return M
