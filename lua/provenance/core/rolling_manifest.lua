--- The ROLLING SEAL — per-session manifests the recorder maintains as it works.
--- Pure Lua port of log-core's `rolling-manifest.ts`. Types + builder +
--- validators only; no I/O. The write side lives in
--- `recorder/io/rolling_seal_writer.lua`.
---
--- ## Why this exists
---
--- A classic bundle is sealed once, by an explicit `:ProvenanceSeal`, into
--- `.provenance/manifest.json` + `manifest.sig`. That works because there is a
--- packaging step to hook: the student runs seal, gets a `.zip`, uploads it.
---
--- A git-submitted assignment has no such step. The student pushes; the grader
--- clones. Nothing ever runs seal, so a git-submitted `.provenance/` would carry
--- no signed manifest at all and every scope would report `no_seal`. The fix is
--- to move the seal off the submission event and onto the recording itself: the
--- recorder rewrites a seal of its own session on every checkpoint, so
--- **whatever is committed is always a valid seal of the state at that moment**.
---
--- ## Why per-session filenames, and why that is not cosmetic
---
--- The rolling seal lives at `.provenance/manifest-<session_id>.json` (+ `.sig`).
---
--- In a shared group repo two partners' recorders both write into the SAME
--- `.provenance/` directory, and both partners push. A single shared
--- `manifest.json` would then conflict on literally every merge — two different
--- signed blobs at one path, which git cannot reconcile and a student cannot
--- hand-resolve without destroying a signature. Per-session filenames make the
--- directory **add-only**: each recorder only ever writes files named after its
--- own session, so a merge is a union of disjoint paths. That is the identical
--- property that already makes `session-<uuid>.slog` mergeable, applied to the
--- seal.
---
--- It follows that each rolling manifest covers **only its own session** and is
--- signed by **that session's** ephemeral key. Nothing needs a key it does not
--- have; verification stays per-session; a partner's sessions verify against a
--- partner's keys.
---
--- ## Format version 1.2
---
--- A rolling manifest is a BundleManifest at `format_version = "1.2"`. It reuses
--- the 1.1 field set verbatim — `assignment_id`, `semester`, `extension_hash`,
--- `sessions`, `submission_files` — and adds exactly one rule, which is why it
--- needs a version of its own rather than being a 1.1 with one session:
---
---   **A rolling manifest FILE describes exactly one session, whose
---   `session_id` is non-null and equals the id in its filename.**
---
--- The filename binding is what stops a rolling manifest being copied sideways:
--- `manifest-A.json` claiming session B would be verified against B's pubkey but
--- read as A's seal. `M.validate_session_manifest` is the one place that rule is
--- enforced, so no reader can forget it.
---
--- ## The `final` marker — closing the append hole
---
--- A rolling seal is signed BEFORE the log's trailing bytes exist. It is
--- rewritten at session start, at every checkpoint, and at teardown, hashing the
--- `.slog` as it stands at that moment, so its `slog_sha256` legitimately
--- commits only to a PREFIX. That is not a defect — it is what stops an honest
--- mid-session archive being read as tampering — but it costs something real: an
--- entry appended past the final checkpoint is indistinguishable from honest
--- mid-session growth.
---
--- `final = true` is what recovers that. The recorder writes it on exactly one
--- roll: the teardown one, taken after `session.end` has been emitted and the
--- writer flushed, when the log provably will not grow again.
---
---   final seal      => WHOLE-FILE. Any append, truncation or edit fails.
---   non-final seal  => PREFIX, exactly as before. Honest growth is never a finding.
---
--- Three properties make this safe rather than a new way to accuse people:
---
---  1. **It is inside the signed payload.** The whole manifest is canonicalized
---     and signed, so a student cannot add `final`, flip it, or strip it from a
---     seal without the session's private key. Doing so breaks check 1.
---  2. **Absence is never a finding.** A session that dies without a clean
---     teardown — a crash, a power cut, a full disk, a read-only `.provenance/`,
---     the directory removed by a `git checkout` — simply has no final seal, and
---     falls back to prefix semantics with the unattested tail REPORTED. Those
---     are documented, expected failure paths; every one of them belongs to a
---     student who did nothing wrong. This is exactly why finality is an
---     explicit, signed claim by the WRITER rather than something a reader
---     infers from the presence of a `session.end` entry: `session.end` is in the
---     log, and the log is the thing whose completeness is in question.
---  3. **It is a one-way ratchet.** `final` only ever tightens what the reader
---     will accept. There is no shape of this field that makes a bundle easier
---     to forge.
---
--- **The key is OMITTED entirely when not final — never written as `false`.**
--- The canonical bytes are the signed message and they are pinned by
--- cross-language conformance vectors that two other recorder implementations
--- verify against; a non-final rolling manifest must stay byte-identical to what
--- 1.2 emitted before this field existed.
---
--- ## What a rolling manifest does NOT change
---
--- Nothing about `manifest.json` / `manifest.sig`. A classic sealed bundle is
--- byte-for-byte what it was: same 1.1 manifest, same canonical bytes, same
--- signature, same loader path. The rolling seal is a second, additive shape.
---
--- ## No user-derived object keys
---
--- Every key in the signed payload is a fixed ASCII identifier chosen by us.
--- `core/json.lua` sorts object keys bytewise while the JS and Kotlin
--- canonicalizers sort by UTF-16 code unit; they agree only for ASCII. Nothing
--- here promotes a session id, assignment id or path to a key — ids and paths
--- are only ever VALUES — so the three canonicalizers cannot diverge.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local bundle = require("provenance.core.bundle")

local M = {}

--- `format_version` of a rolling seal.
M.FORMAT_VERSION = "1.2"

--- `manifest-<session_id>.json` / `manifest-<session_id>.sig`.
---
--- The session-id character class matches the one `session-<uuid>.slog` files
--- use (hex + dashes), so a rolling manifest can only ever be named after
--- something that could be a session id. `manifest.json` and `manifest.sig`
--- cannot match: the `-` after `manifest` is mandatory and the id is non-empty.
--- A `.tmp` staging name cannot match either, since the extension group is
--- anchored to the end of the string and admits no `.`.
local ROLLING_MANIFEST_PATTERN = "^manifest%-([0-9a-f%-]+)%.([a-z]+)$"

local PART_NAMES = { json = true, sig = true }

-- Treat both Lua nil and vim.json.decode's null sentinel as "no value", plus
-- core/json's own NULL — a manifest reaches these validators either as a
-- freshly built value-model table or as a decoded on-disk file.
local function is_null(v)
  return v == nil or v == vim.NIL or v == json.NULL
end

-- ---------------------------------------------------------------------------
-- Filenames
-- ---------------------------------------------------------------------------

--- The two filenames a session's rolling seal occupies inside `.provenance/`.
--- @param session_id string
--- @return table { json = string, sig = string }
function M.filenames(session_id)
  return {
    json = "manifest-" .. session_id .. ".json",
    sig = "manifest-" .. session_id .. ".sig",
  }
end

--- Read a `.provenance/` entry name as a rolling-seal file.
---
--- Returns nil for anything that is not one — including `manifest.json` and
--- `manifest.sig`, which belong to the CLASSIC seal and must never be produced
--- or consumed by the rolling path.
--- @param filename string
--- @return table|nil { session_id = string, part = "json"|"sig" }
function M.parse_filename(filename)
  if type(filename) ~= "string" then
    return nil
  end
  local session_id, part = filename:match(ROLLING_MANIFEST_PATTERN)
  if session_id == nil or not PART_NAMES[part] then
    return nil
  end
  return { session_id = session_id, part = part }
end

-- ---------------------------------------------------------------------------
-- Builder
-- ---------------------------------------------------------------------------

--- Build the json value-model 1.2 rolling manifest for exactly one session.
---
--- This is the single construction path: the writer uses it, and the
--- conformance suite drives it, so the bytes pinned by the golden vectors are
--- the bytes the recorder actually signs.
---
--- @param input table {
---   assignment_id, semester, extension_hash,
---   session_id, prev_session_id (string|nil),
---   slog_sha256, meta_sha256,
---   submission_files = { { path, status, sha256 }, ... },
---   final = boolean|nil   -- OMITTED unless exactly `true`
--- }
--- @return table manifest_value, ready for bundle.to_canonical()/bundle.sign()
function M.build(input)
  return bundle.build({
    format_version = M.FORMAT_VERSION,
    assignment_id = input.assignment_id,
    semester = input.semester,
    extension_hash = input.extension_hash,
    sessions = {
      {
        session_id = input.session_id,
        prev_session_id = input.prev_session_id,
        slog_sha256 = input.slog_sha256,
        meta_sha256 = input.meta_sha256,
      },
    },
    submission_files = input.submission_files or {},
    -- Passed through verbatim: bundle.build emits the key only when this is
    -- exactly `true`, so a non-final roll is byte-identical to a pre-`final`
    -- 1.2 manifest.
    final = input.final,
  })
end

-- ---------------------------------------------------------------------------
-- Validation
-- ---------------------------------------------------------------------------

--- Enforce the rolling-seal FILE rule on an already shape-validated manifest.
---
--- @param manifest_value table  a BundleManifest (value model or decoded JSON)
--- @param expected_session_id string|nil  the id from the FILENAME, when the
---   caller has one. Omit only when reading a manifest that did not come from a
---   named file.
--- @return table  { ok = true, value } | { ok = false, error = { kind, ... } }
---   error kinds:
---     not_rolling          -- format_version is not "1.2"
---     wrong_session_count  -- a rolling manifest FILE covers exactly one session
---     null_session_id      -- the covered session's id is null
---     session_id_mismatch  -- the manifest names a session its filename does not
function M.validate_session_manifest(manifest_value, expected_session_id)
  if type(manifest_value) ~= "table" then
    return result.err({ kind = "not_rolling", format_version = tostring(manifest_value) })
  end

  local version = manifest_value.format_version
  if version ~= M.FORMAT_VERSION then
    return result.err({ kind = "not_rolling", format_version = tostring(version) })
  end

  local sessions = manifest_value.sessions
  local count = (type(sessions) == "table") and #sessions or 0
  if count ~= 1 then
    return result.err({ kind = "wrong_session_count", count = count })
  end

  local only = sessions[1]
  if type(only) ~= "table" or is_null(only.session_id) then
    return result.err({ kind = "null_session_id" })
  end

  if expected_session_id ~= nil and only.session_id ~= expected_session_id then
    return result.err({
      kind = "session_id_mismatch",
      expected = expected_session_id,
      actual = only.session_id,
    })
  end

  return result.ok(manifest_value)
end

--- Does this seal claim to be the LAST one its session will get?
---
--- The single definition of finality, for the same reason `parse_filename` is
--- the single definition of the filename rule: every reader that chooses
--- whole-file over prefix semantics must choose it the same way. Strictly
--- `== true`, so a manifest carrying anything else — a truthy string, a 1, an
--- absent key, `json.NULL` — falls back to the SAFER prefix reading and cannot
--- be tricked into strictness. (Lua makes this trap sharper than JS does: `0`
--- and `""` are both truthy here, so a bare `if m.final then` would be wrong.)
--- @param manifest_value table
--- @return boolean
function M.is_final(manifest_value)
  return type(manifest_value) == "table" and manifest_value.final == true
end

--- Human-readable form of a validate_session_manifest error, for check details.
--- @param error_value table
--- @return string
function M.describe_error(error_value)
  local kind = error_value and error_value.kind
  if kind == "not_rolling" then
    return "format_version is " .. tostring(error_value.format_version) .. ", not " .. M.FORMAT_VERSION
  elseif kind == "wrong_session_count" then
    return "a rolling manifest must cover exactly one session, found " .. tostring(error_value.count)
  elseif kind == "null_session_id" then
    return "the covered session has a null session_id"
  elseif kind == "session_id_mismatch" then
    return "filename names session "
      .. tostring(error_value.expected)
      .. " but the manifest covers "
      .. tostring(error_value.actual)
  end
  return "unknown rolling manifest error"
end

return M
