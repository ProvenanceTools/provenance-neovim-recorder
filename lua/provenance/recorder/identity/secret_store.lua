--- Student master secret + per-course enrollment storage (program spec §5a).
---
--- ## Where the secrets live, and why here
---
--- One JSON file, mode 0600, in a mode-0700 directory under
--- `vim.fn.stdpath("data")` — i.e. `~/.local/share/nvim/provenance/identity.json`
--- on Linux, `~/Library/Application Support/nvim/...` on macOS.
---
--- The VS Code recorder uses `SecretStorage`, the OS credential vault. **Neovim
--- has no credential vault**, so this is the deliberate analogue rather than a
--- shortcut. What matters is the properties, and this location has the ones that
--- drove that choice:
---
---  - **Per-user and per-machine, never per-project.** A student takes many
---    courses in many workspaces and must present the same identity in all of
---    them. `stdpath("data")` is exactly that scope.
---  - **Outside every project directory.** The master secret is the one value
---    that lets someone sign as this student in EVERY course, forever. A
---    workspace dotfile would be committed to a git-submission repo by accident
---    and would be readable by a lab partner sharing a 61B repo — which is the
---    actual threat model, not a hypothetical one.
---  - **Nowhere `.provenance/` or seal can reach.** Anything under a workspace's
---    `.provenance/` is swept into the submission bundle by
---    `commands/seal.lua`. Putting a private key there would ship it to the
---    grader. This path cannot be reached by that sweep.
---
--- Rejected alternatives: a workspace dotfile (committed / partner-readable, as
--- above); anything under `.provenance/` (packed into the bundle); an
--- environment variable (leaks into `ps` output and shell history); `vim.g` or a
--- session file (not persistent, and written into `:mksession` output).
---
--- **This is not encryption.** File permissions are the whole protection: a
--- process running as the student can read it, exactly as it could read their
--- keyring once unlocked. What it defends against is the realistic case — a
--- shared machine, a lab partner with a login, and a git repo that gets pushed.
---
--- ## Moving to a new machine
---
--- There is no escrow and no server-side key store, by design, so nobody can
--- recover this for a student. `:ProvenanceIdentityExport` prints the 64-hex
--- secret; `:ProvenanceIdentityImport` adopts it on the new machine. Per-course
--- keys then re-derive byte-identically through HKDF, so every enrollment token
--- the student already holds keeps working and nothing is re-minted.
---
--- ## Why enrollment tokens live here too
---
--- A token is a signed PUBLIC statement, not a secret — it is written verbatim
--- into `session.start`. It is stored beside the master secret anyway so there
--- is exactly ONE persistence mechanism to reason about: a wiped or unreadable
--- store then loses both together, which reads unambiguously as "not enrolled"
--- rather than as a half-state where a token exists but its key does not.
---
--- ## `course_id` as a storage key is fine
---
--- Enrollments are keyed by `course_id` in this file's JSON. That is a STORAGE
--- key, never a JCS object key: nothing in this file is ever canonicalized or
--- signed, and it is written with `vim.json.encode`, never `json.canonicalize`.
--- The permanent no-user-derived-object-keys constraint (see
--- `core/course_cert.lua`) is about canonicalization key ORDERING and does not
--- reach here.
local core_enrollment = require("provenance.core.enrollment")
local student_keys = require("provenance.core.student_keys")
local result = require("provenance.core.result")
local atomic_write = require("provenance.recorder.io.atomic_write")

local M = {}

--- Storage format version for this file itself (unrelated to any log format).
M.FORMAT_VERSION = "1.0"

local MASTER_HEX_LEN = student_keys.MASTER_SECRET_BYTES * 2

--- Default on-disk location. Exposed so a student (or a bug report) can name it.
--- @return string
function M.default_path()
  return vim.fn.stdpath("data") .. "/provenance/identity.json"
end

local function to_hex(bytes)
  return (bytes:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end

local function from_hex(hex)
  return (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

local function is_master_hex(v)
  return type(v) == "string" and #v == MASTER_HEX_LEN and v:match("^[0-9a-f]+$") ~= nil
end

--- Students copy the secret out of a message, so a stray newline, surrounding
--- whitespace, or an uppercase rendering must not read as corruption.
local function normalize_hex(raw)
  if type(raw) ~= "string" then
    return ""
  end
  return (raw:gsub("%s+", "")):lower()
end

--- Create a store bound to a file path.
--- @param opts table|nil { path?: string }  path defaults to M.default_path()
--- @return table store
function M.new(opts)
  opts = opts or {}
  local path = opts.path or M.default_path()

  local store = { path = path }

  --- Read + decode the whole file. Never throws.
  --- @return table|nil state, string|nil err_reason
  local function read_state()
    local uv = vim.uv or vim.loop
    local st = uv.fs_stat(path)
    if not st then
      return nil, nil -- absent is not an error; it is "nothing stored yet"
    end
    local fd = uv.fs_open(path, "r", 384) -- 384 = 0o600
    if not fd then
      return nil, "unreadable"
    end
    local ok, data = pcall(function()
      local fstat = uv.fs_fstat(fd)
      if not fstat then
        error("fstat failed")
      end
      return uv.fs_read(fd, fstat.size, 0) or ""
    end)
    uv.fs_close(fd)
    if not ok then
      return nil, "unreadable"
    end
    local decode_ok, decoded = pcall(vim.json.decode, data)
    if not decode_ok or type(decoded) ~= "table" then
      return nil, "corrupt_file"
    end
    return decoded, nil
  end

  --- Atomically rewrite the file, then tighten permissions on it and its
  --- directory. Written with vim.json.encode, NEVER json.canonicalize: nothing
  --- here is signed, and canonicalize would reject the arbitrary course_id keys.
  local function write_state(state)
    local uv = vim.uv or vim.loop
    local dir = path:match("(.*)/[^/]*$")
    if dir and dir ~= "" then
      vim.fn.mkdir(dir, "p")
      pcall(uv.fs_chmod, dir, tonumber("700", 8))
    end
    atomic_write.atomic_write_file(path, vim.json.encode(state))
    -- After the rename, not before: the temp file carries the umask's mode and
    -- the rename preserves it, so the final file is what must be tightened.
    pcall(uv.fs_chmod, path, tonumber("600", 8))
  end

  local function load_or_empty()
    local state, err = read_state()
    if err ~= nil then
      return nil, err
    end
    if state == nil then
      return { format_version = M.FORMAT_VERSION, enrollments = vim.empty_dict() }, nil
    end
    if type(state.enrollments) ~= "table" then
      state.enrollments = vim.empty_dict()
    end
    return state, nil
  end

  -- -------------------------------------------------------------------------
  -- Master secret
  -- -------------------------------------------------------------------------

  --- Read the stored master secret WITHOUT creating one.
  --- @return table { ok = true, value = <32 raw bytes> } | { ok = false, error = { kind, reason? } }
  function store.load_master_secret()
    local state, err = read_state()
    if err ~= nil then
      return result.err({ kind = "store_unavailable", reason = err })
    end
    if state == nil or state.master_secret == nil then
      return result.err({ kind = "no_master_secret" })
    end
    if not is_master_hex(state.master_secret) then
      -- NEVER overwritten. A mis-encoded value may still be recoverable by hand,
      -- and silently replacing it would invalidate every token the student
      -- holds — every past bundle would then carry an identity they can no
      -- longer reproduce.
      return result.err({
        kind = "corrupt_master_secret",
        reason = "expected " .. MASTER_HEX_LEN .. " hex characters",
      })
    end
    return result.ok(from_hex(state.master_secret))
  end

  --- Read the master secret, generating and persisting one on first use.
  --- A corrupt stored value is an ERROR, never a regeneration trigger.
  --- @return table
  function store.load_or_create_master_secret()
    local existing = store.load_master_secret()
    if existing.ok then
      return existing
    end
    if existing.error.kind ~= "no_master_secret" then
      return existing
    end

    local state, err = load_or_empty()
    if err ~= nil then
      return result.err({ kind = "store_unavailable", reason = err })
    end
    local fresh = student_keys.generate_master_secret()
    state.master_secret = to_hex(fresh)
    local write_ok, write_err = pcall(write_state, state)
    if not write_ok then
      return result.err({ kind = "store_unavailable", reason = tostring(write_err) })
    end
    return result.ok(fresh)
  end

  --- Hex-encode the stored master secret for transfer to a new machine.
  --- @return table { ok = true, value = <64-char hex> } | err
  function store.export_master_secret()
    local loaded = store.load_master_secret()
    if not loaded.ok then
      return loaded
    end
    return result.ok(to_hex(loaded.value))
  end

  --- Adopt a master secret pasted from another machine.
  --- A malformed paste leaves any existing secret UNTOUCHED — overwriting on a
  --- typo would be unrecoverable.
  --- @param raw string
  --- @return table { ok = true, value = true } | err
  function store.import_master_secret(raw)
    local hex = normalize_hex(raw)
    if not is_master_hex(hex) then
      return result.err({
        kind = "corrupt_master_secret",
        reason = "expected " .. MASTER_HEX_LEN .. " hex characters, got " .. #hex,
      })
    end
    local state, err = load_or_empty()
    if err ~= nil then
      return result.err({ kind = "store_unavailable", reason = err })
    end
    state.master_secret = hex
    local write_ok, write_err = pcall(write_state, state)
    if not write_ok then
      return result.err({ kind = "store_unavailable", reason = tostring(write_err) })
    end
    return result.ok(true)
  end

  -- -------------------------------------------------------------------------
  -- Enrollment tokens
  -- -------------------------------------------------------------------------

  --- Validate a pasted `{ enrollment, enrollment_cert }` blob and persist it
  --- under the course the token names.
  ---
  --- Shape and version only — SIGNATURES ARE NOT CHECKED HERE, because the trust
  --- anchor for that is a workspace manifest's root-verified `course_cert`,
  --- which is not in scope at import time. The real check happens at session
  --- start in `session_identity.lua`, against the manifest actually being
  --- recorded. Validating here only rejects an obvious paste error while the
  --- student is standing there to fix it.
  --- @param raw_json string
  --- @return table { ok = true, value = { course_id } } | { ok = false, error = { kind, ... } }
  function store.save_enrollment(raw_json)
    local decode_ok, parsed = pcall(vim.json.decode, raw_json)
    if not decode_ok or type(parsed) ~= "table" or vim.islist(parsed) then
      return result.err({ kind = "invalid_json", message = "expected a JSON object" })
    end

    -- Version gate BEFORE shape, mirroring verify_identity_chain step 0: a
    -- future 3.0 artifact must be rejected as a version problem, never read
    -- under 2.0 rules.
    for _, pair in ipairs({ { "enrollment_cert", "cert" }, { "enrollment", "token" } }) do
      local field, artifact = pair[1], pair[2]
      local declared = type(parsed[field]) == "table" and parsed[field].format_version or nil
      if declared ~= core_enrollment.FORMAT_VERSION then
        return result.err({
          kind = "unsupported_format_version",
          artifact = artifact,
          format_version = type(declared) == "string" and declared or "",
        })
      end
    end

    local cert = core_enrollment.parse_enrollment_cert(parsed.enrollment_cert)
    if not cert.ok then
      return result.err({ kind = "invalid_cert_shape", reason = cert.error.reason })
    end
    local token = core_enrollment.parse_enrollment_token(parsed.enrollment)
    if not token.ok then
      return result.err({ kind = "invalid_token_shape", reason = token.error.reason })
    end

    -- Caught here as well as in the chain walk: storing a pair that can never
    -- verify would leave the student "enrolled" while every session silently
    -- omitted an identity.
    if token.value.course_id ~= cert.value.course_id then
      return result.err({
        kind = "course_id_mismatch",
        token_course_id = token.value.course_id,
        cert_course_id = cert.value.course_id,
      })
    end

    local state, err = load_or_empty()
    if err ~= nil then
      return result.err({ kind = "store_unavailable", reason = err })
    end
    state.enrollments[token.value.course_id] = {
      enrollment = token.value,
      enrollment_cert = cert.value,
    }
    local write_ok, write_err = pcall(write_state, state)
    if not write_ok then
      return result.err({ kind = "store_unavailable", reason = tostring(write_err) })
    end
    return result.ok({ course_id = token.value.course_id })
  end

  --- Read the stored enrollment for one course.
  ---
  --- Returns nil for EVERY failure — absent, unreadable file, corrupt blob. This
  --- is on the session-start path, where the only correct response to "cannot
  --- produce an identity" is to record without one.
  --- @param course_id string
  --- @return table|nil { enrollment, enrollment_cert }
  function store.load_enrollment(course_id)
    local state, err = read_state()
    if err ~= nil or state == nil or type(state.enrollments) ~= "table" then
      return nil
    end
    local blob = state.enrollments[course_id]
    if type(blob) ~= "table" then
      return nil
    end
    local cert = core_enrollment.parse_enrollment_cert(blob.enrollment_cert)
    local token = core_enrollment.parse_enrollment_token(blob.enrollment)
    if not cert.ok or not token.ok then
      return nil
    end
    return { enrollment = token.value, enrollment_cert = cert.value }
  end

  --- Forget one course's enrollment. Never touches the master secret.
  --- @param course_id string
  function store.clear_enrollment(course_id)
    local state, err = read_state()
    if err ~= nil or state == nil or type(state.enrollments) ~= "table" then
      return
    end
    state.enrollments[course_id] = nil
    pcall(write_state, state)
  end

  --- Course ids with a stored enrollment, sorted. For the status command.
  --- @return string[]
  function store.enrolled_courses()
    local state, err = read_state()
    if err ~= nil or state == nil or type(state.enrollments) ~= "table" then
      return {}
    end
    local out = {}
    for course_id in pairs(state.enrollments) do
      out[#out + 1] = course_id
    end
    table.sort(out)
    return out
  end

  return store
end

return M
