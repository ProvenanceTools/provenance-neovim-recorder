--- Pointing an un-enrolled student at the enrollment page.
---
--- Mirrors `packages/recorder/src/activation/enroll-nudge.ts` in the VS Code
--- recorder and `EnrollNudge.kt` in the JetBrains one; keep the three in step.
---
--- A student who never enrols still records perfectly good bundles -- the event
--- stream, the hash chain and the seal are all unaffected (rule 1 in
--- `identity/session_identity.lua`). What they lose is ATTRIBUTION: nothing in
--- the bundle says who produced it. That failure is silent, it is the default
--- state of every fresh install, and until this module existed its only trace
--- was a `_identity_outcome` field kept as a test seam.
---
--- ## Why this reads the identity outcome instead of looking up a credential
---
--- "Is this student enrolled?" looks like a one-line store lookup, and a lookup
--- gets it wrong. A student holding a LEGACY 2.0 course token has no 2.1
--- credential stored, so the lookup calls them un-enrolled -- but their sessions
--- DO emit an identity and their work IS attributed. Telling them otherwise
--- would be false, and would push them to re-enrol for nothing.
---
--- `session_identity.build` has already answered the real question, both
--- families handled. This module consumes that answer.
---
--- ## Not every skip is the student's problem
---
--- Of the ten skip reasons, only two mean "you have no credential and enrolling
--- would fix it" -- see `is_unenrolled_skip`. Attaching an enrollment URL to a
--- packaging bug would send the student somewhere that cannot help them and bury
--- the real fault.
---
--- ## No network, still
---
--- Recorder PRD NG2 forbids the recorder making network calls during a session.
--- Nothing here fetches. The URL is a string the student is shown; opening it is
--- their own `:ProvenanceEnroll`, in their own browser, and enrollment stays a
--- paste in both directions (`commands/enrollment.lua`).
---
--- Pure: no Neovim API. `enroll_nudge_ui.lua` is the glue that renders it.

local M = {}

--- The enrollment page.
---
--- Hardcoded, and deliberately not a setting. Every institution running this
--- recorder today is Berkeley, and the value cannot be derived from anything an
--- un-enrolled student holds: `institution_id` lives inside the credential and
--- the institution cert, which is exactly what a student who has not enrolled
--- does not have. The manifest carries no institution field at all.
---
--- When a second institution appears this becomes a signed manifest field or a
--- setting -- and that is when it deserves a design, with the `institution_id`
--- already in the credential to key off.
M.ENROLL_URL = "https://provenance.eecs.berkeley.edu/enroll"

--- How far the student has got with the nudge. Persisted per MACHINE, globally
--- -- never per course. A 2.1 credential is institution-scoped and covers every
--- course at once, so a student taking 61B and 61C is one person with one
--- enrollment and must be nudged once, not once per assignment root.
M.STATES = { UNSEEN = "unseen", INTENT = "intent", DONE = "done" }

--- What the student did with the notification.
---
--- `DISPLAYED` has no counterpart in the other two recorders and exists because
--- Neovim's `vim.notify` carries no buttons: there is no click to observe, so
--- "they dismissed it" is unknowable here. Advancing on DISPLAY instead keeps
--- the lifetime ceiling of two notifications that the other recorders enforce
--- through their button handlers.
M.ACTIONS = {
  ENROLL = "enroll",
  SHOW_KEY = "show_key",
  DISMISS = "dismiss",
  DISPLAYED = "displayed",
}

M.MESSAGE = "Provenance is recording, but you have not enrolled -- this work will not be "
  .. "attributed to you.\nEnrol at "
  .. M.ENROLL_URL
  .. " (or run :ProvenanceEnroll), then\n:ProvenanceEnrollmentRequest for your key and "
  .. ":ProvenanceEnrollmentImport for the credential."

--- Anything unrecognised (absent file, older build, hand-edited state) reads as fresh.
--- @param raw any
--- @return string one of M.STATES
function M.parse_state(raw)
  if raw == M.STATES.INTENT or raw == M.STATES.DONE then
    return raw
  end
  return M.STATES.UNSEEN
end

--- Does this skip reason mean the student has no credential and enrolling fixes it?
---
--- Only two of the ten do:
---
---  - `not_enrolled` -- the 2.0 path found no token for this course.
---  - `manifest_not_2_0` -- reached ONLY after the 2.1 lookup found no credential
---    (see the precedence block in `session_identity.build`), so it means "no 2.1
---    credential, and the manifest is too old to carry a 2.0 anchor". Enrolling
---    yields a 2.1 credential, the 2.1 path then runs first, and the manifest
---    version stops mattering. So: actionable.
---
--- Everything else is withheld deliberately:
---
---  - `no_root_public_key`, `institution_cert_not_root_signed` -- the build
---    shipped without a usable trust anchor. Not fixable by enrolling, and a web
---    page would hide a packaging fault that needs staff.
---  - `master_secret_unavailable` -- the identity store is unreadable. Enrolling
---    needs that same store, so the advice would fail on arrival.
---  - `credential_key_mismatch`, `student_key_mismatch` -- they HAVE a
---    credential; it belongs to another machine. Already messaged, in more
---    detail, at the moment of import.
---  - the rest -- something is wrong that a student cannot act on.
--- @param reason table|nil
--- @return boolean
function M.is_unenrolled_skip(reason)
  if type(reason) ~= "table" then
    return false
  end
  return reason.kind == "not_enrolled" or reason.kind == "manifest_not_2_0"
end

--- Did any session claim an identity?
---
--- All-or-nothing on purpose. With several assignment roots open a 2.1
--- credential covers all of them, so mixed outcomes are only reachable by a
--- legacy 2.0 holder enrolled in some courses and not others. For that student
--- plain "recording" is the honest statusline: at least one session IS
--- attributed. The per-course gap surfaces where it belongs -- on the analyzer,
--- against the submission that lacks a contributor.
--- @param outcomes table[] list of { kind = "emitted"|"skipped", ... }
--- @return boolean
function M.any_identity_emitted(outcomes)
  for _, o in ipairs(outcomes or {}) do
    if type(o) == "table" and o.kind == "emitted" then
      return true
    end
  end
  return false
end

--- Should the student see "(not enrolled)"?
---
--- True only when no session emitted an identity AND at least one skipped for a
--- reason enrolling would fix. A machine whose identity store is broken reads as
--- plain "recording": the identity is missing, but "not enrolled" would be the
--- wrong diagnosis and the wrong instruction.
--- @param outcomes table[]
--- @return boolean
function M.is_unenrolled(outcomes)
  if M.any_identity_emitted(outcomes) then
    return false
  end
  for _, o in ipairs(outcomes or {}) do
    if type(o) == "table" and o.kind == "skipped" and M.is_unenrolled_skip(o.reason) then
      return true
    end
  end
  return false
end

--- Show the nudge this session?
---
--- `done` is terminal. `unseen` and `intent` both show, capping the student's
--- lifetime exposure at two notifications.
--- @param outcomes table[]
--- @param state string
--- @return boolean
function M.should_show(outcomes, state)
  if state == M.STATES.DONE then
    return false
  end
  return M.is_unenrolled(outcomes)
end

--- The state to persist after the student acts (or after the nudge is shown).
---
--- Dismissing means no, and no is permanent -- a student who has decided must
--- not be asked again. Everything else advances one step, which buys exactly one
--- follow-up: the browser opens, real life intervenes, and the credential never
--- gets pasted. The second nudge catches that. There is no third, because by
--- then the persistent "(not enrolled)" statusline segment has said it every
--- session and a notification is nagging.
--- @param current string
--- @param action string
--- @return string
function M.next_state(current, action)
  if current == M.STATES.DONE then
    return M.STATES.DONE
  end
  if action == M.ACTIONS.DISMISS then
    return M.STATES.DONE
  end
  if current == M.STATES.UNSEEN then
    return M.STATES.INTENT
  end
  return M.STATES.DONE
end

--- The statusline suffix for the enrollment state.
--- @param unenrolled boolean
--- @return string
function M.segment_suffix(unenrolled)
  return unenrolled and " (not enrolled)" or ""
end

return M
