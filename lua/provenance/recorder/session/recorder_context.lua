--- Builds the session.start payload (SessionStartPayload, PRD §5.1).
--- Pure(ish) function — every environment value (hostname, username, nvim
--- version, platform, recorder version, uuid generator) is injectable via
--- `env` so tests are fully deterministic. Mirrors log-core's
--- buildRecorderContext (recorder-context.ts).
---
--- CLAUDE.md: "test the event-to-log-entry transformation as a pure
--- function, separately from the editor wiring."
local core_sha256 = require("provenance.core.sha256")
local core_json = require("provenance.core.json")
local bit = require("bit")
local band, bor = bit.band, bit.bor

local M = {}

-- No package.json in a Neovim plugin; this is the single source of truth
-- for the recorder's own version until Plan 9 (dist) sources it centrally
-- (e.g. from a generated version file or the plugin manifest).
local PLUGIN_VERSION = "0.2.0"

-- Pinned producer id (design.md §6 / CLAUDE.md "Producer identity"): this is
-- how the analyzer distinguishes hosts. Never rename or derive this.
local EXTENSION_ID = "com.provenance.recorder.nvim"

--- Generate a UUID v4 (RFC 4122) from 16 random bytes, lowercase hex,
--- version nibble forced to 4 and variant bits forced to 10xx.
local function generate_uuid()
  local uv = vim.uv or vim.loop
  local bytes = uv.random(16)

  local b = {}
  for i = 1, 16 do
    b[i] = string.byte(bytes, i)
  end

  b[7] = bor(band(b[7], 0x0F), 0x40) -- version 4
  b[9] = bor(band(b[9], 0x3F), 0x80) -- variant 10xx

  local hex = {}
  for i = 1, 16 do
    hex[i] = string.format("%02x", b[i])
  end

  return table.concat(hex, "", 1, 4)
    .. "-"
    .. table.concat(hex, "", 5, 6)
    .. "-"
    .. table.concat(hex, "", 7, 8)
    .. "-"
    .. table.concat(hex, "", 9, 10)
    .. "-"
    .. table.concat(hex, "", 11, 16)
end

local function default_username()
  return os.getenv("USER") or os.getenv("USERNAME") or "unknown"
end

local function default_hostname()
  local uv = vim.uv or vim.loop
  local ok, uname = pcall(function() return uv.os_uname() end)
  if ok and uname and uname.nodename and uname.nodename ~= "" then
    return uname.nodename
  end
  local ok2, name = pcall(vim.fn.hostname)
  if ok2 and name and name ~= "" then
    return name
  end
  return "unknown"
end

local function default_platform()
  local uv = vim.uv or vim.loop
  local ok, uname = pcall(function() return uv.os_uname() end)
  if ok and uname and uname.sysname then
    return uname.sysname
  end
  return "unknown"
end

local function default_nvim_version()
  local ok, v = pcall(vim.version)
  if not ok or not v then
    return "unknown"
  end
  return string.format("%d.%d.%d", v.major or 0, v.minor or 0, v.patch or 0)
end

--- Compute machine_id = sha256Hex(hostname .. ":" .. username .. ":" .. session_id).
--- session_id is a per-session salt (mirrors log-core's computeMachineId).
local function compute_machine_id(hostname, username, session_id)
  return core_sha256.hex(hostname .. ":" .. username .. ":" .. session_id)
end

--- Build the `manifest` block carried by session.start 2.0 (program spec §5):
--- the FULL manifest — payload + sig +, at 2.0, `course_cert` and `policy`.
---
--- Emitted for 1.x manifests too. That is the point: it is what lets the
--- analyzer apply the ABSENCE-VS-DISABLED rule, i.e. tell "this student
--- produced no selection.change events" from "this course disabled
--- selection.change" — a distinction heuristics otherwise mis-fire on. A 1.x
--- manifest simply carries no policy, which reads as the default capture set.
---
--- `files_under_review` is re-tagged as a json.array so it canonicalizes as
--- `[...]` and not `{...}`: this payload is hashed into the chain, and an
--- untagged list from a hand-built manifest would produce different bytes.
--- Fields are copied by name rather than by table copy so an unknown key on the
--- source manifest can never silently enter the signed chain.
local function build_manifest_block(m)
  local block = {
    assignment_id = m.assignment_id,
    semester = m.semester,
    issued_at = m.issued_at,
    files_under_review = core_json.array(m.files_under_review or {}),
    sig = m.sig,
  }

  -- Absent on a hand-built 1.x manifest; core.manifest.parse always sets it.
  block.format_version = m.format_version

  -- 2.0-only. Nil assignment is a no-op in Lua, so a 1.x manifest simply omits
  -- every one of these and its block is exactly the 1.x manifest.
  block.course_id = m.course_id
  block.collaboration = m.collaboration
  block.submission = m.submission
  block.scope = m.scope
  block.policy = m.policy
  block.course_cert = m.course_cert

  return block
end

--- @param opts table {manifest, prev_session_id, session_pubkey_hex, env?}
---   manifest: table with assignment_id, semester, sig.
---   prev_session_id: string or nil (fresh session).
---   session_pubkey_hex: string or nil.
---   env: optional overrides — uuid (function -> string), hostname, username,
---     nvim_version, platform, recorder_version.
--- @return table SessionStartPayload
function M.build_recorder_context(opts)
  opts = opts or {}
  local manifest = opts.manifest
  local env = opts.env or {}

  local uuid_fn = env.uuid or generate_uuid
  local session_id = uuid_fn()

  local hostname = env.hostname or default_hostname()
  local username = env.username or default_username()
  local nvim_version = env.nvim_version or default_nvim_version()
  local platform = env.platform or default_platform()
  local recorder_version = env.recorder_version or PLUGIN_VERSION

  local machine_id = compute_machine_id(hostname, username, session_id)

  local prev_session_id = opts.prev_session_id
  if prev_session_id == nil then
    prev_session_id = core_json.NULL
  end

  return {
    format_version = "1.0",
    session_id = session_id,
    prev_session_id = prev_session_id,
    assignment = {
      id = manifest.assignment_id,
      semester = manifest.semester,
    },
    manifest_sig = manifest.sig,
    machine_id = machine_id,
    -- The FULL manifest (program spec §5). NEW in 2.0, additive: 1.x readers
    -- ignore what they do not know.
    manifest = build_manifest_block(manifest),
    -- RETAINED for 1.x readers, which look here for the host triple. `host`
    -- below is its 2.0 replacement; both are emitted during the transition.
    vscode = {
      version = nvim_version,
      commit = "",
      platform = platform,
    },
    -- NEW in 2.0: the editor-neutral host block that replaces `vscode`.
    -- `editor_build` is "" because Neovim has no build-commit concept — the
    -- spec explicitly permits the empty string (VS Code does not expose one
    -- either). NOTE: deliberately NO `identity` block. Enrollment keys are
    -- sub-project S2 and do not exist yet; the field is optional precisely so
    -- this can land first, and emitting an empty or invented one would be a
    -- claim the recorder cannot back.
    host = {
      editor = "neovim",
      editor_version = nvim_version,
      editor_build = "",
      platform = platform,
    },
    recorder = {
      version = recorder_version,
      extension_id = EXTENSION_ID,
    },
    session_pubkey = opts.session_pubkey_hex or "",
  }
end

return M
