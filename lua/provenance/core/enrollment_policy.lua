--- Enrollment policy — the professor-facing control over whether the recorder
--- treats an un-enrolled student as needing attention. Lua port of
--- log-core's `policy.ts` `resolveEnrollmentPolicy`.
---
--- The block lives INSIDE the course-signed manifest payload, alongside
--- `policy.capture` (`core/capture_policy.lua`):
---
---   "policy": {
---     "capture": { ... },
---     "enrollment": { "required": false }
---   }
---
--- ## Why this exists
---
--- A student who never enrols still records a perfectly good bundle — the
--- event stream, the hash chain and the seal are all unaffected
--- (`recorder/enroll_nudge.lua`'s header). All they lose is ATTRIBUTION, which
--- only matters for group work. For a large first-week course where
--- attribution is not being used yet, the recorder telling every unenrolled
--- student they are "not enrolled" is a false alarm that panics novices for no
--- product reason. `policy.enrollment.required = false` lets a course turn
--- that alarm off, cosmetically only: it changes nothing about the recorded
--- bytes, the hash chain, or a student's ability to enrol and get attribution
--- if they want it.
---
--- ## Default is `required: true`
---
--- Absent `policy`, absent `enrollment`, absent `required`, or ANY malformed
--- value (wrong type, `json.NULL`) all resolve to `true` — exactly today's
--- behaviour. Every existing manifest, and every manifest with a typo'd or
--- future-shaped `enrollment` block, is unaffected. This mirrors
--- `capture_policy.resolve`'s per-key fallback rule: a course can only ever
--- turn detection DOWN, never accidentally trigger a new failure mode by
--- getting the shape wrong.
---
--- ## This module does not know about format versions
---
--- Precisely like `capture_policy.lua`: `resolve` treats whatever `block` it is
--- handed as trustworthy. The caller — `recorder/enrollment_policy_gate.lua` —
--- is responsible for handing this module `nil` on anything below
--- Manifest 2.0, because `policy` is only inside the signed payload from 2.0
--- onward. See that module for the security rationale (a student cannot staple
--- `enrollment: {required: false}` onto their own statusline to hide the
--- nudge from a course that actually requires enrolment — that is a strictly
--- SMALLER worry than the equivalent capture-policy bypass, since silencing
--- your own "not enrolled" notice costs you your own attribution, not anyone
--- else's — but the gate applies uniformly regardless, so as not to special-case
--- one signed-payload key's trust rule against all the others sharing `policy`).
---
--- ## Permanent constraint: no user-derived object keys
---
--- `enrollment` and `required` are both fixed ASCII identifiers, satisfying the
--- bytewise-vs-UTF-16 sort constraint stated in `capture_policy.lua` and
--- `manifest.lua`. Any future addition under `policy.enrollment` must be too.
---
--- Pure: no Neovim editor APIs, no I/O, and resolution is total — any absent,
--- malformed, or out-of-range input yields a well-defined value, so nothing
--- here returns a Result or throws.
local json = require("provenance.core.json")

local M = {}

--- Applied when the manifest carries no `policy` block, no `policy.enrollment`
--- key, or a malformed one. Enrollment is required — i.e. exactly the
--- behaviour before this module existed.
M.DEFAULTS = {
  required = true,
}

-- Same null-aware object check as capture_policy.lua: JSON `null` reaches here
-- either as `vim.NIL` (raw `vim.json.decode`) or `json.NULL` (the manifest
-- module's normalized value model). Neither is an enrollment object.
local function is_plain_object(v)
  if type(v) ~= "table" then
    return false
  end
  if v == json.NULL or v == vim.NIL then
    return false
  end
  return not json.is_array(v)
end

local function resolve_bool(value, fallback)
  if type(value) == "boolean" then
    return value
  end
  return fallback
end

--- Resolve a manifest `policy` block into the effective enrollment policy.
---
--- Total by construction. A missing block, a block with no `enrollment` key, or
--- an `enrollment` value that is not a plain object all resolve to
--- M.DEFAULTS. A non-boolean `required` (including `json.NULL`) falls back to
--- the default `true` rather than being treated as false — the Lua-specific
--- hazard: `required = false` and `required = nil`/absent are different at the
--- JSON level even though both are falsy in Lua, and `resolve_bool` above
--- distinguishes them correctly by checking `type(value) == "boolean"` rather
--- than truthiness.
--- @param block table|nil  the manifest's `policy` value, or nil
--- @return table  { required: boolean }
function M.resolve(block)
  local defaults = M.DEFAULTS
  if not is_plain_object(block) then
    return vim.tbl_extend("force", {}, defaults)
  end

  local enrollment = block.enrollment
  if not is_plain_object(enrollment) then
    return vim.tbl_extend("force", {}, defaults)
  end

  return {
    required = resolve_bool(enrollment.required, defaults.required),
  }
end

return M
