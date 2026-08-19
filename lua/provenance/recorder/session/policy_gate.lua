--- policy_gate.lua — the capture policy, compiled into the two cheap lookups
--- SessionHost needs on the emit path (program spec §4).
---
--- The professor-facing control: a course can turn capture DOWN, a student
--- cannot turn it OFF. Two kinds of control, both handled here:
---
--- Exactly one kind of control remains: **event kinds**. `selection.change`,
--- `focus.change` and `terminal.*` each have a `policy.capture` key. Everything
--- else is on the HARD FLOOR and has no key at all — the schema is the
--- enforcement mechanism, so this module never re-implements the floor as a
--- list of exceptions. It asks `capture_policy.is_event_kind_captured`, which
--- returns true for any kind with no key.
---
--- There is deliberately NO payload redaction here any more. An earlier
--- `inline_content` knob stripped the content fields from `paste` and
--- `fs.external_change`; it was retired because `internal_move` needs that
--- content to DOWNGRADE a `large_paste` flag, so stripping it made the system
--- more accusatory, not more private. `doc_open_close` went the same way —
--- `doc.open` carries the reconstruction seed. See capture_policy.lua for the
--- general rule those two removals establish.
---
--- NOTE: the 64 KB inline size cap lives in the payload builders
--- (events/paste_payload.lua, events/external_change_content.lua) and is an
--- entirely separate mechanism. It was never a policy knob and is untouched.
---
--- ## Why the gate is an object handed to SessionHost, not logic inside it
---
--- Suppression MUST happen before an entry is chained and assigned a `seq`
--- (see session_host.lua). That forces the check into `host.emit`. But
--- SessionHost owns seq/prev_hash and nothing else — teaching it which payload
--- fields belong to a `paste` would put format knowledge in the one module
--- that must stay a pure chaining primitive. So the knowledge lives here, in
--- the recorder layer, and SessionHost only ever asks an injected gate.
---
--- ## Compiled, because emit is the firehose
---
--- `doc.change` fires per keystroke and must stay well under 1 ms. The decision
--- is therefore precomputed in `new()` into a table that is EMPTY in the common
--- case (everything enabled), so `allows` is a single failed hash lookup. Never
--- a policy re-resolve, never a manifest re-parse, and never any crypto.
local capture_policy = require("provenance.core.capture_policy")

local M = {}

--- The effective capture policy for an ALREADY-VERIFIED manifest.
---
--- **Only a 2.0 manifest may carry a policy.** Below 2.0 the `policy` block is
--- not inside the signed payload, so honouring one would hand students exactly
--- the capture off switch that the chain's step-0 gate exists to deny them: a
--- student could staple `policy: {capture: {...false}}` onto a genuinely signed
--- 1.x manifest and silence their own recorder. A 1.x manifest therefore always
--- resolves to DEFAULTS — which is precisely the v1.x capture set, so legacy
--- behaviour is unchanged.
--- @param manifest table|nil
--- @return table  a resolved CapturePolicy
function M.effective_policy(manifest)
  if type(manifest) ~= "table" then
    return capture_policy.resolve(nil)
  end
  if manifest.format_version ~= "2.0" then
    return capture_policy.resolve(nil)
  end
  return capture_policy.resolve(manifest.policy)
end

--- Compile a resolved policy into a gate.
--- @param policy table|nil  a resolved CapturePolicy (see capture_policy.resolve)
--- @return table gate { policy, allows(kind) }
function M.new(policy)
  policy = policy or capture_policy.resolve(nil)

  -- Precomputed: kind -> true when the policy switches that kind OFF. Only
  -- gated kinds can ever appear; floor kinds have no key to switch, so
  -- is_event_kind_captured returns true for them and they are never inserted.
  local blocked = {}
  for kind in pairs(capture_policy.POLICY_GATED_EVENT_KINDS) do
    if not capture_policy.is_event_kind_captured(kind, policy) then
      blocked[kind] = true
    end
  end

  local gate = { policy = policy }

  --- May this event kind be recorded at all?
  --- Floor kinds always yield true — there is no key that could turn them off.
  --- @param kind string
  --- @return boolean
  function gate.allows(kind)
    return not blocked[kind]
  end

  return gate
end

return M
