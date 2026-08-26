--- enrollment_policy_gate.lua — the manifest-format-version trust gate for
--- `policy.enrollment`, mirroring `recorder/session/policy_gate.lua`'s
--- `effective_policy` for `policy.capture` exactly.
---
--- `core/enrollment_policy.lua` resolves whatever `policy` block it is handed;
--- it has no opinion on whether that block should be trusted. That opinion
--- belongs here, in the recorder layer, for the same reason it belongs in
--- `policy_gate.lua` rather than in `capture_policy.lua`: **only a 2.0
--- manifest's `policy` field is inside the course-signed payload**
--- (`core/manifest.lua`'s `signed_payload`). Below 2.0, `policy` is just JSON
--- sitting next to a signature that never covered it, so it must be ignored —
--- honouring it would let a student staple `policy: {enrollment: {required:
--- false}}` onto a genuinely signed 1.x manifest.
---
--- That specific bypass is lower-stakes here than the equivalent one
--- `policy_gate.lua` blocks for capture (silencing your OWN "not enrolled"
--- notice costs you your own attribution, not the integrity of anyone's
--- record), but this module applies the identical gate anyway rather than
--- special-casing `enrollment` as "safe to trust early" — `policy` has one
--- trust rule, not one per key, and a 1.x manifest resolving to
--- `required = true` is exactly the pre-existing behaviour regardless.
---
--- Used by `registry.lua` to ANNOTATE each session's identity outcome with
--- whether its course requires enrollment (see its `identity_outcomes()`),
--- and nowhere else — this is a cosmetic gate, not part of the emit path
--- `session/policy_gate.lua` guards. It annotates rather than filters:
--- `enroll_nudge.is_unenrolled`'s asymmetric check needs to see every
--- outcome for its "did anyone emit an identity" half, and only its "does
--- anyone still need to enrol" half is restricted to sessions where this
--- function returns true.
local enrollment_policy = require("provenance.core.enrollment_policy")

local M = {}

--- Does this ALREADY-VERIFIED manifest require enrollment?
---
--- **Only a 2.0 manifest may carry an enrollment policy.** Anything else
--- (missing, non-table, or below format_version "2.0") resolves to
--- `M.DEFAULTS.required` (`true`) — the enrollment-required behaviour that
--- predates this module.
--- @param manifest table|nil
--- @return boolean
function M.effective_required(manifest)
  if type(manifest) ~= "table" then
    return enrollment_policy.DEFAULTS.required
  end
  if manifest.format_version ~= "2.0" then
    return enrollment_policy.DEFAULTS.required
  end
  return enrollment_policy.resolve(manifest.policy).required
end

return M
