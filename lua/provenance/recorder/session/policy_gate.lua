--- policy_gate.lua — the capture policy, compiled into the two cheap lookups
--- SessionHost needs on the emit path (program spec §4).
---
--- The professor-facing control: a course can turn capture DOWN, a student
--- cannot turn it OFF. Two kinds of control, both handled here:
---
---  - **Event kinds.** `selection.change`, `focus.change`, `terminal.*`,
---    `doc.open`/`doc.close` each have a `policy.capture` key. Everything else
---    is on the HARD FLOOR and has no key at all — the schema is the
---    enforcement mechanism, so this module never re-implements the floor as a
---    list of exceptions. It asks `capture_policy.is_event_kind_captured`,
---    which returns true for any kind with no key.
---  - **Inline content.** `paste` and `fs.external_change` are floor kinds and
---    always fire; `inline_content = false` withholds only the inlined bytes.
---    Length, sha256 and size always survive, so the paste heuristics and
---    `mass_external_replacement` still have something to work with.
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
--- `doc.change` fires per keystroke and must stay well under 1 ms. Both
--- decisions are therefore precomputed in `new()` into two tables that are
--- EMPTY in the common case (everything enabled): `allows` and `redact` become
--- a single failed hash lookup each. Never a policy re-resolve, never a
--- manifest re-parse, and never any crypto.
local capture_policy = require("provenance.core.capture_policy")

local M = {}

--- Inline-content fields to strip per kind when `inline_content` is disabled.
--- The retained fields (`length`, `sha256`, `new_content_size`) are deliberately
--- NOT listed: withholding content must never cost the analyzer the ability to
--- size or fingerprint what happened.
local INLINE_CONTENT_FIELDS = {
  ["paste"] = { "content", "content_head", "content_tail" },
  ["fs.external_change"] = { "new_content", "new_content_head", "new_content_tail" },
}

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
--- @return table gate { policy, allows(kind), redact(kind, data) }
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

  -- Precomputed: kind -> fields to strip. Empty unless inline_content is off.
  local strip = {}
  if policy.inline_content == false then
    for kind, fields in pairs(INLINE_CONTENT_FIELDS) do
      strip[kind] = fields
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

  --- Strip withheld inline content from a payload the policy still allows.
  ---
  --- Returns `data` UNCHANGED (same table, no allocation) whenever nothing is
  --- withheld, which is every event on the hot path and every event at all
  --- under the default policy. When something is withheld it returns a shallow
  --- COPY — never mutating the caller's table, because payload builders and
  --- their tests hand the same table to more than one consumer.
  --- @param kind string
  --- @param data table|nil
  --- @return table|nil
  function gate.redact(kind, data)
    local fields = strip[kind]
    if fields == nil or type(data) ~= "table" then
      return data
    end

    local copy = nil
    for _, field in ipairs(fields) do
      if data[field] ~= nil then
        if copy == nil then
          copy = {}
          for k, v in pairs(data) do
            copy[k] = v
          end
        end
        copy[field] = nil
      end
    end
    return copy or data
  end

  return gate
end

return M
