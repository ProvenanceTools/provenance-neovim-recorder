--- Shape-validation and window primitives shared by the two identity families.
--- Lua port of log-core's `identity-shapes.ts`.
---
--- INTERNAL to `core/`. It exists because `enrollment.lua` (the legacy
--- course-scoped chain, identity format_version 2.0) and `institution.lua` (the
--- institution-scoped chain that replaces it, 2.1) must validate their artifacts
--- with byte-identical rules. Two copies of "is this an ISO 8601 bound" is
--- exactly how two ports of the same rule drift apart — and this file is a port
--- of a port, so the hazard is doubled here.
---
--- Nothing here does signature work. Everything here runs BEFORE signature work,
--- for the reason spelled out in both callers: a canonicalizer OMITS keys whose
--- value is absent, so an artifact missing a required field would otherwise sign
--- and verify perfectly while carrying nothing at that field.
---
--- Pure: no Neovim editor APIs, no I/O, nothing that throws.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local course_cert = require("provenance.core.course_cert")

local M = {}

--- 64-byte ed25519 signature, lowercase hex.
M.HEX_128 = 128
--- 32-byte ed25519 public key or seed, lowercase hex.
M.HEX_64 = 64

--- @param v any
--- @param n integer  exact character count
--- @return boolean
function M.is_hex(v, n)
  return type(v) == "string" and #v == n and v:match("^[0-9a-f]+$") ~= nil
end

--- A table that is neither a tagged JSON array nor the JSON null sentinel.
--- @param v any
--- @return boolean
function M.is_plain_object(v)
  return type(v) == "table" and not json.is_array(v) and v ~= json.NULL
end

--- Validate a required non-empty string field.
---
--- A missing key and a null-valued key are treated identically —
--- canonicalization erases the difference, so nothing downstream may rely on it.
--- @param obj table
--- @param field string
--- @return table  { ok = true, value = string } | { ok = false, error = { reason, field } }
function M.require_string(obj, field)
  local v = obj[field]
  if type(v) ~= "string" or v == "" then
    return result.err({ reason = "must be a non-empty string", field = field })
  end
  return result.ok(v)
end

--- Validate a required lowercase-hex field of an exact length.
--- @param obj table
--- @param field string
--- @param n integer
--- @return table
function M.require_hex(obj, field, n)
  if not M.is_hex(obj[field], n) then
    return result.err({ reason = "must be a " .. n .. "-char hex string", field = field })
  end
  return result.ok(obj[field])
end

--- Validate an ordered pair of ISO 8601 bounds.
---
--- Both bounds MUST parse. Short validity windows are the only offline
--- mitigation either identity scheme has for the absence of revocation, so a
--- bound that silently never binds would undercut the sole control there is.
--- These artifacts are new, so unlike `manifest.issued_at` there is no
--- archived-data compatibility cost to enforcing it.
--- @param obj table
--- @param lower_field string
--- @param upper_field string
--- @return table  { ok = true, value = { lower, upper } } | err
function M.require_ordered_bounds(obj, lower_field, upper_field)
  local parsed = {}
  for _, field in ipairs({ lower_field, upper_field }) do
    local as_string = M.require_string(obj, field)
    if not as_string.ok then
      return as_string
    end
    local ms = course_cert.parse_iso_instant_ms(as_string.value)
    if ms == nil then
      return result.err({ reason = "must be an ISO 8601 date or timestamp", field = field })
    end
    parsed[field] = ms
  end
  if parsed[lower_field] > parsed[upper_field] then
    return result.err({
      reason = "must not be earlier than " .. lower_field,
      field = upper_field,
    })
  end
  return result.ok({ lower = obj[lower_field], upper = obj[upper_field] })
end

--- Shared window arithmetic: is `at` inside `[lower, upper]`?
---
--- `lower` is inclusive from its first instant; a date-only `upper` is inclusive
--- through the END of that day, via course_cert.resolve_valid_until_exclusive_ms.
--- Identical semantics to course_cert.check_window, deliberately reusing the same
--- two primitives so the asymmetric date rule is implemented exactly ONCE in this
--- port.
---
--- `at` is always a RELEVANT ISSUE TIME, never wall-clock now — see the callers.
--- @param lower string
--- @param upper string
--- @param at string
--- @return table  { in_window = true } | { in_window = false, reason = ... }
function M.check_window(lower, upper, at)
  local from = course_cert.parse_iso_instant_ms(lower)
  local until_exclusive = course_cert.resolve_valid_until_exclusive_ms(upper)
  local instant = course_cert.parse_iso_instant_ms(at)

  if from == nil or until_exclusive == nil or instant == nil then
    return { in_window = false, reason = "unparseable_timestamp" }
  end
  if instant < from then
    return { in_window = false, reason = "before_valid_from" }
  end
  if instant >= until_exclusive then
    return { in_window = false, reason = "after_valid_until" }
  end
  return { in_window = true }
end

--- Shared ed25519 verification. Every malformed input is a verification FAILURE
--- rather than an error: these values arrive from a student-editable file, so a
--- bad hex string is an expected condition, not an exceptional one.
--- @param ed25519 table  the crypto module (injected to keep this file's require
---   list minimal and to make the seam explicit)
--- @param payload string
--- @param sig_hex any
--- @param pubkey_hex any
--- @return boolean  never throws
function M.verify_detached(ed25519, payload, sig_hex, pubkey_hex)
  local ok, verified = pcall(function()
    if not M.is_hex(sig_hex, M.HEX_128) or not M.is_hex(pubkey_hex, M.HEX_64) then
      return false
    end
    return ed25519.verify(ed25519.from_hex(sig_hex), payload, pubkey_hex)
  end)
  if not ok then
    return false
  end
  return verified == true
end

return M
