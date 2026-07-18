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
local PLUGIN_VERSION = "0.1.0"

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
    vscode = {
      version = nvim_version,
      commit = "",
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
