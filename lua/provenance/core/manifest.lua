--- Manifest parse + verify — the activation gate primitive.
--- Mirrors log-core's `manifest.ts`: a `.provenance-manifest` file the course
--- instructor signs and drops into the assignment workspace. The recorder only
--- activates (starts recording) inside a workspace whose manifest verifies
--- (design.md §4.1).
---
--- Two format versions live here.
---
--- **1.x** (design.md §4.1) has no `format_version` field at all, so 1.x
--- manifests are identified by its *absence*. Signed payload:
---
---   canonicalize({assignment_id, semester, issued_at, files_under_review})
---
--- **2.0** (program spec §3, 2026-08-18-multicourse-program-architecture)
--- carries two independent signature scopes in one file: a COURSE-signed
--- payload and a ROOT-signed `course_cert` that authorizes the course key.
--- Signed payload:
---
---   canonicalize({format_version, course_id, assignment_id, semester,
---                 issued_at, files_under_review, ignore, attachments,
---                 collaboration, submission, scope, policy})
---
--- `signed_payload` excludes `sig` in both versions, and excludes `course_cert`
--- in 2.0 — the course does not sign its own certificate.
---
--- **1.x parsing is supported permanently.** Archived submissions must still
--- validate years later; that adjudication case is what justifies the whole
--- program. A missing `format_version` defaults to `"1.0"` and parses
--- successfully — it never rejects.
---
--- ## Permanent constraint: no user-derived object keys
---
--- Every key in the signed payload is a fixed ASCII identifier chosen by us,
--- and every future addition must be too — never a course id, assignment id,
--- path, or other user-supplied string promoted to a key. `core/json.lua` sorts
--- object keys bytewise while the JS and Kotlin canonicalizers sort by UTF-16
--- code unit; they agree only for ASCII. `policy` is the one signed field with
--- open-ended contents, so it is the one place a non-ASCII key could enter —
--- `validate_signed_subtree` below rejects that at parse time, matching
--- log-core's `sanitizeSignedValue`.
---
--- parse() validates JSON + field shapes and never throws. verify() and
--- verify_chain() never throw either, returning false / an err Result on any
--- malformed input.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local ed25519 = require("provenance.core.ed25519")
local course_cert = require("provenance.core.course_cert")
local path_scope = require("provenance.core.path_scope")

local M = {}

--- The format version of a manifest with no `format_version` field.
M.FORMAT_VERSION_LEGACY = "1.0"

--- The version at which the trust chain and capture policy appear.
M.FORMAT_VERSION_2 = "2.0"

local COLLABORATION_VALUES = { solo = true, group = true }
local SUBMISSION_VALUES = { bundle = true, git = true }
local SCOPE_VALUES = { directory = true, repo = true }

-- Map a vim.json.decode result into the json value model (same convention as
-- ndjson.lua's normalize): null -> json.NULL, JSON arrays get tagged with
-- json.array so is_array()/canonicalize can tell them apart from objects.
local function normalize(v)
  if v == vim.NIL then return json.NULL end
  if type(v) ~= "table" then return v end
  if vim.tbl_isempty(v) then
    return getmetatable(v) and {} or json.array({})
  end
  if vim.islist(v) then
    local out = json.array({})
    for i = 1, #v do out[i] = normalize(v[i]) end
    return out
  end
  local out = {}
  for k, val in pairs(v) do out[k] = normalize(val) end
  return out
end

--- Exposed so a caller holding a raw `vim.json.decode` result (rather than
--- manifest text) can bring it into the value model `parse_value` expects.
M.normalize = normalize

local function is_nonempty_string(v)
  return type(v) == "string" and v ~= ""
end

local function is_128_hex(v)
  return type(v) == "string" and #v == 128 and v:match("^[0-9a-f]+$") ~= nil
end

local function is_64_hex(v)
  return type(v) == "string" and #v == 64 and v:match("^[0-9a-f]+$") ~= nil
end

--- Validate an attacker-influenced sub-tree destined for the signed payload.
--- `policy` is the only signed field with open-ended contents, so it is the
--- only place these hazards can enter. Two things are enforced:
---
---  - **Printable-ASCII object keys.** The permanent constraint above: this
---    module's canonicalizer sorts keys bytewise while JS and Kotlin sort by
---    UTF-16 code unit, and the orderings diverge above U+007F. The same
---    manifest would then verify on one recorder and fail on another.
---  - **Finite numbers.** `json.canonicalize` raises on NaN/Infinity; rejecting
---    here turns that into a value rather than an error.
---
--- Key ORDER is not preserved and does not need to be: JCS sorts keys.
---
--- Unlike log-core's `sanitizeSignedValue` this validates in place instead of
--- deep-rebuilding: the rebuild exists there to strip `toJSON` methods and
--- accessor properties, neither of which a Lua table can carry.
local function validate_signed_subtree(value, path)
  if value == json.NULL then
    return result.ok(true)
  end
  local ty = type(value)
  if ty == "boolean" or ty == "string" then
    return result.ok(true)
  end
  if ty == "number" then
    if value ~= value or value == math.huge or value == -math.huge then
      return result.err({ reason = "must be a finite number", field = path })
    end
    return result.ok(true)
  end
  if ty ~= "table" then
    return result.err({ reason = "must be JSON data", field = path })
  end

  if json.is_array(value) then
    for i = 1, #value do
      local child = validate_signed_subtree(value[i], path .. "[" .. i .. "]")
      if not child.ok then
        return child
      end
    end
    return result.ok(true)
  end

  for k, v in pairs(value) do
    if type(k) ~= "string" or k:match("^[\32-\126]+$") == nil then
      return result.err({ reason = "object keys must be printable ASCII", field = path })
    end
    local child = validate_signed_subtree(v, path .. "." .. k)
    if not child.ok then
      return child
    end
  end
  return result.ok(true)
end

--- Validate one path-scope list. Used for all THREE lists at 2.0 — `ignore`,
--- `attachments`, and (at 2.0 only) `files_under_review`, whose entries must
--- also satisfy the entry grammar there. Port of log-core's `checkScopeList`.
---
--- **At 1.x this is NOT called at all** (see the module docstring): 1.x
--- parsing must never reject, and a 1.x manifest's entries carry exact-path
--- meaning regardless of how they are spelled — an entry ending in `/` there
--- means a file literally named that, not a directory prefix.
--- @param value unknown
--- @param field string
--- @return table|nil  {reason, field} on failure, nil if `value` is legal
local function check_scope_list(value, field)
  if type(value) ~= "table" or not json.is_array(value) then
    return { reason = "must be an array", field = field }
  end
  for i = 1, #value do
    local entry = value[i]
    if type(entry) ~= "string" then
      return { reason = "all elements must be strings", field = field }
    end
    local problem = path_scope.validate_scope_entry(entry)
    if problem ~= nil then
      return { reason = string.format('"%s": %s', entry, problem.detail), field = field }
    end
  end
  return nil
end

--- Resolve a manifest's format version.
---
--- **A missing `format_version` means "1.0".** 1.x manifests have no such
--- field; treating its absence as anything else would break every archived
--- submission. Non-negotiable (program spec §3).
--- @param m table
--- @return string
function M.format_version(m)
  local v = m.format_version
  if type(v) == "string" then
    return v
  end
  return M.FORMAT_VERSION_LEGACY
end

--- Validate an already-decoded, normalized manifest value.
---
--- Needed as its own entry point because a manifest does not only arrive as
--- file text: verify_chain must re-validate whatever object it is handed, and
--- program spec §5 puts the full manifest inside `session.start`. Without this,
--- a consumer would hand an unchecked object to verify_chain — which is exactly
--- how "the chain verified" stops implying "the course signed a policy".
---
--- Expects the json value model (arrays tagged via json.array, nulls as
--- json.NULL). Run M.normalize first on a raw vim.json.decode result.
--- @param obj table
--- @return table  { ok = true, value = Manifest } | { ok = false, error = { reason, field? } }
function M.parse_value(obj)
  if type(obj) ~= "table" or json.is_array(obj) or obj == json.NULL then
    return result.err({ reason = "not_object" })
  end

  -- format_version: absent means 1.0. Never a rejection reason on its own.
  if obj.format_version ~= nil and type(obj.format_version) ~= "string" then
    return result.err({ reason = "invalid", field = "format_version" })
  end
  local format_version = M.format_version(obj)
  local is_v2 = format_version == M.FORMAT_VERSION_2
  if not is_v2 and format_version:sub(1, 2) ~= "1." then
    -- Rejected rather than guessed at: silently canonicalizing an unknown
    -- version under the wrong rules would surface as a signature failure with
    -- a misleading cause.
    return result.err({ reason = "unsupported format_version", field = "format_version" })
  end

  -- Required non-empty string fields.
  for _, field in ipairs({ "assignment_id", "semester", "issued_at" }) do
    local v = obj[field]
    if v == nil then
      return result.err({ reason = "missing", field = field })
    end
    if not is_nonempty_string(v) then
      return result.err({ reason = "invalid", field = field })
    end
  end

  -- files_under_review: array of strings.
  local files = obj.files_under_review
  if files == nil then
    return result.err({ reason = "missing", field = "files_under_review" })
  end
  if type(files) ~= "table" or not json.is_array(files) then
    return result.err({ reason = "invalid", field = "files_under_review" })
  end
  for i = 1, #files do
    if type(files[i]) ~= "string" then
      return result.err({ reason = "invalid", field = "files_under_review" })
    end
  end

  -- sig: 128-char lowercase hex.
  local sig = obj.sig
  if sig == nil then
    return result.err({ reason = "missing", field = "sig" })
  end
  if not is_128_hex(sig) then
    return result.err({ reason = "sig must be 128-char hex", field = "sig" })
  end

  local parsed = {
    format_version = format_version,
    assignment_id = obj.assignment_id,
    semester = obj.semester,
    issued_at = obj.issued_at,
    files_under_review = files, -- already json.array-tagged by normalize()
    sig = sig,
  }

  if not is_v2 then
    return result.ok(parsed)
  end

  -- --- 2.0-only fields, ALL required -------------------------------------
  --
  -- Requiring the full set keeps the signed key set fixed, which is what lets
  -- three hand-written canonicalizers agree without each reproducing a "which
  -- optional keys were present" rule.

  if not is_nonempty_string(obj.course_id) then
    return result.err({ reason = "invalid", field = "course_id" })
  end

  -- `ignore` and `attachments`: REQUIRED at 2.0. `[]` is the explicit "I do
  -- not use this" spelling; absence is a rejection. Requiring the full set
  -- keeps the signed key set fixed, which is what lets the Kotlin and Lua
  -- ports canonicalize identically without reproducing a "which optional
  -- keys were present" rule.
  local ignore_problem = check_scope_list(obj.ignore, "ignore")
  if ignore_problem ~= nil then
    return result.err(ignore_problem)
  end
  local attachments_problem = check_scope_list(obj.attachments, "attachments")
  if attachments_problem ~= nil then
    return result.err(attachments_problem)
  end
  -- files_under_review already passed the array/string check in the shared
  -- section above; at 2.0 its entries must also satisfy the entry grammar.
  local track_problem = check_scope_list(files, "files_under_review")
  if track_problem ~= nil then
    return result.err(track_problem)
  end

  local enums = {
    { field = "collaboration", allowed = COLLABORATION_VALUES },
    { field = "submission", allowed = SUBMISSION_VALUES },
    { field = "scope", allowed = SCOPE_VALUES },
  }
  for _, e in ipairs(enums) do
    local v = obj[e.field]
    if type(v) ~= "string" or not e.allowed[v] then
      return result.err({ reason = "invalid", field = e.field })
    end
  end

  local policy = obj.policy
  if type(policy) ~= "table" or json.is_array(policy) or policy == json.NULL then
    return result.err({ reason = "invalid", field = "policy" })
  end
  local policy_ok = validate_signed_subtree(policy, "policy")
  if not policy_ok.ok then
    return policy_ok
  end

  if obj.course_cert == nil then
    return result.err({ reason = "missing", field = "course_cert" })
  end
  local cert = course_cert.parse(obj.course_cert)
  if not cert.ok then
    return result.err({
      reason = cert.error.reason,
      field = cert.error.field and ("course_cert." .. cert.error.field) or "course_cert",
    })
  end

  parsed.course_id = obj.course_id
  -- Already json.array-tagged by normalize() (same convention as
  -- files_under_review above).
  parsed.ignore = obj.ignore
  parsed.attachments = obj.attachments
  parsed.collaboration = obj.collaboration
  parsed.submission = obj.submission
  parsed.scope = obj.scope
  -- Contents kept verbatim (unknown keys included) so the signed bytes
  -- round-trip byte-for-byte through verification.
  parsed.policy = policy
  parsed.course_cert = cert.value
  return result.ok(parsed)
end

--- @param text string  raw manifest JSON text
--- @return table  { ok = true, value = Manifest } | { ok = false, error = { reason, field? } }
function M.parse(text)
  local decode_ok, decoded = pcall(vim.json.decode, text, { luanil = { object = false, array = false } })
  if not decode_ok then
    return result.err({ reason = "invalid_json", message = tostring(decoded) })
  end
  return M.parse_value(normalize(decoded))
end

--- Build the exact byte string the course tool signs.
---
--- `sig` is always excluded. In 2.0 `course_cert` is excluded too — the course
--- does not sign its own certificate. `files_under_review` must be tagged as a
--- json.array so it canonicalizes as `[...]`, not `{...}`.
---
--- For a 1.x manifest this produces **exactly** the bytes it produced before
--- Manifest 2.0 existed: the same four fields, no `format_version`. Existing
--- signatures on archived manifests therefore keep verifying forever.
---
--- JCS orders keys, so the literal order below has no effect on the output.
--- @param m table
--- @return string
function M.signed_payload(m)
  if M.format_version(m) == M.FORMAT_VERSION_2 then
    return json.canonicalize({
      format_version = M.FORMAT_VERSION_2,
      course_id = m.course_id,
      assignment_id = m.assignment_id,
      semester = m.semester,
      issued_at = m.issued_at,
      files_under_review = json.array(m.files_under_review),
      ignore = json.array(m.ignore),
      attachments = json.array(m.attachments),
      collaboration = m.collaboration,
      submission = m.submission,
      scope = m.scope,
      policy = m.policy,
    })
  end

  return json.canonicalize({
    assignment_id = m.assignment_id,
    semester = m.semester,
    issued_at = m.issued_at,
    files_under_review = json.array(m.files_under_review),
  })
end

--- Verify the ed25519 signature on a parsed Manifest.
---
--- **This is NOT chain verification.** At 2.0 it answers only "did this public
--- key sign this payload", and the key you would naturally reach for —
--- `m.course_cert.course_pubkey` — comes out of a student-editable file.
--- Calling verify(m, m.course_cert.course_pubkey) and treating the result as
--- trust is self-referential and proves nothing. Use M.verify_chain, which
--- roots the key in the root signature first.
---
--- @param m table  a Manifest (typically the .value of a successful parse())
--- @param pubkey_hex string  64-char hex ed25519 public key. For a 2.0 manifest
---   this is `course_cert.course_pubkey`; for 1.x, the embedded course key.
--- @return boolean  never throws; false on any malformed input
function M.verify(m, pubkey_hex)
  local ok, verified = pcall(function()
    if type(m) ~= "table" then return false end
    if not is_64_hex(pubkey_hex) then return false end
    if not is_nonempty_string(m.assignment_id) then return false end
    if not is_nonempty_string(m.semester) then return false end
    if not is_nonempty_string(m.issued_at) then return false end
    if type(m.files_under_review) ~= "table" then return false end
    for i = 1, #m.files_under_review do
      if type(m.files_under_review[i]) ~= "string" then return false end
    end
    if not is_128_hex(m.sig) then return false end

    if M.format_version(m) == M.FORMAT_VERSION_2 then
      if not is_nonempty_string(m.course_id) then return false end
      if not COLLABORATION_VALUES[m.collaboration] then return false end
      if not SUBMISSION_VALUES[m.submission] then return false end
      if type(m.scope) ~= "string" or not SCOPE_VALUES[m.scope] then return false end
      if type(m.policy) ~= "table" then return false end
    end

    return ed25519.verify(ed25519.from_hex(m.sig), M.signed_payload(m), pubkey_hex)
  end)
  if not ok then return false end
  return verified == true
end

--- Walk the full Manifest 2.0 trust chain: root -> course_cert -> manifest.
--- Program spec §3. **The steps run in this order and the order is
--- load-bearing.**
---
--- 0. Assert `format_version == "2.0"` BEFORE walking the chain at all. This
---    gate is a security control, not a formality. At 1.x, `course_id`,
---    `collaboration`, `submission`, `scope` and `policy` are NOT in the signed
---    payload — so a student holding any legitimately issued 1.x manifest from
---    their own course could staple on that course's certificate (public,
---    root-signed, freely copyable out of any 2.0 manifest), add a matching
---    `course_id` to satisfy step 3, and staple on an invented `policy`
---    disabling all capture. Every individual signature would verify. Without
---    step 0 the policy block's entire reason for living inside the signed
---    payload is defeated and students get the off switch.
--- 0b. Validate the 2.0 shape before any signature work: a canonicalizer omits
---    keys whose value is absent, so a 2.0 manifest missing `policy` entirely
---    would sign and chain cleanly while carrying no policy at all.
--- 1. `course_cert` minus `root_sig` verifies against the embedded root pubkey.
--- 2. The payload minus `sig` and `course_cert` verifies against
---    `course_cert.course_pubkey`.
--- 3. `manifest.course_id == course_cert.course_id`. Not a formality: without
---    it, CS 61B's course key can sign a manifest whose `course_id` says
---    `berkeley-cs61c` and steps 1 and 2 both pass — the cert really is
---    root-signed and the payload really is signed by the key it authorizes.
---    Only comparing the two ids catches it.
--- 4. `issued_at` falls within `[valid_from, valid_until]`, both inclusive.
---    Evaluated against `issued_at`, NEVER wall-clock now, and **non-fatal**:
---    an out-of-window result is returned on the SUCCESS value as `window`, not
---    as an error. A course that lets a cert lapse mid-semester must not have
---    recording silently stop for a whole class (program spec §4).
---
--- @param m table  a Manifest — parsed, or lifted from a session.start payload
--- @param root_pubkey_hex string  the embedded ROOT public key. A PARAMETER;
---   this module never hardcodes it.
--- @return table
---   { ok = true, value = { course_id, course_pubkey, cert, window } }
---   | { ok = false, error = { kind = "not_manifest_2_0", format_version } }
---   | { ok = false, error = { kind = "missing_course_cert" } }
---   | { ok = false, error = { kind = "invalid_manifest_shape", field?, reason? } }
---   | { ok = false, error = { kind = "invalid_root_signature" } }
---   | { ok = false, error = { kind = "invalid_course_signature" } }
---   | { ok = false, error = { kind = "course_id_mismatch", manifest_course_id, cert_course_id } }
function M.verify_chain(m, root_pubkey_hex)
  if type(m) ~= "table" then
    return result.err({ kind = "invalid_manifest_shape", reason = "not_object" })
  end

  -- Step 0 — the chain exists only at 2.0.
  local declared = M.format_version(m)
  if declared ~= M.FORMAT_VERSION_2 then
    return result.err({ kind = "not_manifest_2_0", format_version = declared })
  end

  if m.course_cert == nil then
    return result.err({ kind = "missing_course_cert" })
  end

  -- Step 0b — re-validate the WHOLE manifest, not just the certificate: `m`
  -- may have been hand-built, or lifted straight out of a session.start
  -- payload without going through parse().
  local validated = M.parse_value(m)
  if not validated.ok then
    return result.err({
      kind = "invalid_manifest_shape",
      field = validated.error.field,
      reason = validated.error.reason,
    })
  end
  local checked = validated.value
  local cert = checked.course_cert

  -- Step 1 — cert vs root.
  if not course_cert.verify(cert, root_pubkey_hex) then
    return result.err({ kind = "invalid_root_signature" })
  end

  -- Step 2 — payload vs course_pubkey. Safe to trust that key here, and only
  -- here, because step 1 just rooted the certificate carrying it.
  if not M.verify(checked, cert.course_pubkey) then
    return result.err({ kind = "invalid_course_signature" })
  end

  -- Step 3 — the manifest may not claim a course its cert does not cover.
  if checked.course_id ~= cert.course_id then
    return result.err({
      kind = "course_id_mismatch",
      manifest_course_id = checked.course_id,
      cert_course_id = cert.course_id,
    })
  end

  -- Step 4 — non-fatal validity window, evaluated against issued_at.
  return result.ok({
    course_id = cert.course_id,
    course_pubkey = cert.course_pubkey,
    cert = cert,
    window = course_cert.check_window(cert, checked.issued_at),
  })
end

--- The three scope lists as a `path_scope.resolve_path_role`-shaped scope
--- table: `{track, ignore, attachments}`. Port of log-core's
--- `scopeFromManifest`, and the ONLY way a consumer should build one.
---
--- A 1.x manifest has neither `ignore` nor `attachments` — both default to
--- empty, which resolves every path exactly as 1.x always behaved (every
--- `files_under_review` entry `"reviewed"`, everything else `"unscoped"`).
--- @param m table  a Manifest (typically the .value of a successful parse())
--- @return table {track: string[], ignore: string[], attachments: string[]}
function M.scope_from_manifest(m)
  return {
    track = m.files_under_review,
    ignore = m.ignore or {},
    attachments = m.attachments or {},
  }
end

return M
