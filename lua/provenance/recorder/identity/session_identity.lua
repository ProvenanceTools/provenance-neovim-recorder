--- Build the `session.start.identity` block (program spec §5, §5a step 5).
---
--- This is the one place on the recorder where the student's per-course PRIVATE
--- key is used. It derives that key from the master secret, countersigns this
--- session's ephemeral `session_pubkey`, and assembles
--- `{ enrollment, enrollment_cert, session_pubkey_sig }`.
---
--- ## Two rules, in priority order
---
--- **1. Never block recording.** Every failure below returns `skipped` and the
--- session records without an `identity`. Same reasoning §4 applies to an expired
--- `course_cert`: for an integrity tool, silently not recording is a worse
--- failure than recording under an incomplete credential. A student who has not
--- enrolled yet, whose store is unreadable, or whose course let a cert lapse
--- still produces a bundle with a full, chain-verifiable event stream.
---
--- **2. Never emit an identity that does not verify.** Before returning, the
--- assembled block is walked with `verify_identity_chain` against the manifest's
--- ALREADY-ROOT-VERIFIED `course_cert` — the same walk the analyzer will perform.
--- A block that fails is dropped rather than written, because `session.start` is
--- signed and hash-chained: a broken claim in there is permanent, unrepairable,
--- and looks exactly like tampering during an adjudication.
---
--- ## No network. Ever.
---
--- Recorder PRD NG2. Nothing here fetches. The enrollment token arrives by PASTE
--- (`commands/enrollment.lua`) and everything else is derived locally, so the
--- whole identity path works on a plane.
local core_enrollment = require("provenance.core.enrollment")
local core_manifest = require("provenance.core.manifest")

local M = {}

local function is_hex_64(v)
  return type(v) == "string" and #v == 64 and v:match("^[0-9a-f]+$") ~= nil
end

--- @param input table {
---   manifest: table            -- the ALREADY-VERIFIED manifest for this root.
---                             -- Its course_cert is the trust anchor, so passing
---                             -- an unverified manifest makes the verification
---                             -- below meaningless.
---   session_pubkey_hex: string -- this session's ephemeral public key
---   session_started_at: string -- ISO 8601; the token's window is judged against
---                             -- this, never wall-clock now, so an archived
---                             -- bundle still reads correctly years later
---   store: table               -- a recorder.identity.secret_store instance
---   key_cache: table|nil       -- a recorder.identity.key_cache instance
--- }
--- @return table
---   { kind = "emitted", identity = {...}, verified = {...} }
---   | { kind = "skipped", reason = { kind = ..., ... } }
function M.build(input)
  local ok, outcome = pcall(function()
    local manifest = input.manifest
    local store = input.store

    -- Anchor: there is no identity chain without a course cert to anchor it.
    if type(manifest) ~= "table" then
      return { kind = "skipped", reason = { kind = "manifest_not_2_0" } }
    end
    local course_cert = manifest.course_cert
    local course_id = manifest.course_id
    if
      core_manifest.format_version(manifest) ~= core_manifest.FORMAT_VERSION_2
      or type(course_cert) ~= "table"
      or type(course_id) ~= "string"
      or course_id == ""
    then
      return { kind = "skipped", reason = { kind = "manifest_not_2_0" } }
    end

    if not is_hex_64(input.session_pubkey_hex) then
      return { kind = "skipped", reason = { kind = "invalid_session_pubkey" } }
    end

    if type(store) ~= "table" then
      return { kind = "skipped", reason = { kind = "not_enrolled", course_id = course_id } }
    end

    -- The token for THIS course. Keyed by the manifest's course_id, so an
    -- enrollment in another course reads as "not enrolled" here; the chain
    -- walk's step 3 would reject it anyway.
    local stored = store.load_enrollment(course_id)
    if type(stored) ~= "table" then
      return { kind = "skipped", reason = { kind = "not_enrolled", course_id = course_id } }
    end

    -- The student key. LOADED, never created: a freshly generated secret could
    -- not possibly derive the key an existing token names, so creating one here
    -- would only manufacture a mismatch.
    local master = store.load_master_secret()
    if not master.ok then
      return {
        kind = "skipped",
        reason = { kind = "master_secret_unavailable", reason = master.error.kind },
      }
    end

    local keypair, derive_err
    if input.key_cache ~= nil then
      keypair, derive_err = input.key_cache.get(master.value, course_id)
    else
      local student_keys = require("provenance.core.student_keys")
      local derive_ok, kp = pcall(student_keys.derive_course_keypair, master.value, course_id)
      if derive_ok then
        keypair = kp
      else
        derive_err = tostring(kp)
      end
    end
    if type(keypair) ~= "table" then
      return {
        kind = "skipped",
        reason = { kind = "master_secret_unavailable", reason = derive_err or "derive_failed" },
      }
    end

    if keypair.public_key_hex ~= stored.enrollment.student_pubkey then
      -- Normally a token minted before the student moved machines and imported a
      -- different secret. Signing anyway would produce a countersignature that
      -- cannot verify.
      return {
        kind = "skipped",
        reason = {
          kind = "student_key_mismatch",
          token_student_pubkey = stored.enrollment.student_pubkey,
          derived_pubkey = keypair.public_key_hex,
        },
      }
    end

    -- Countersign this session's ephemeral key. `student_ref` and `course_id`
    -- come from the token, so the signature asserts which student, in which
    -- course, adopted this key — and the verifier cross-checks both.
    local session_pubkey_sig = core_enrollment.sign_session_pubkey({
      course_id = stored.enrollment.course_id,
      student_ref = stored.enrollment.student_ref,
      session_pubkey = input.session_pubkey_hex,
    }, keypair.private_key)

    local identity = {
      enrollment = stored.enrollment,
      enrollment_cert = stored.enrollment_cert,
      session_pubkey_sig = session_pubkey_sig,
    }

    -- Rule 2. Walk it exactly as the analyzer will, BEFORE it becomes part of a
    -- signed chain that can never be amended.
    local walked = core_enrollment.verify_identity_chain({
      identity = identity,
      session_pubkey = input.session_pubkey_hex,
      course_cert = course_cert,
      session_started_at = input.session_started_at,
    })
    if not walked.ok then
      return { kind = "skipped", reason = { kind = "chain_did_not_verify", error = walked.error } }
    end

    -- Out-of-window is deliberately NOT a reason to withhold: expiry is
    -- reported, never enforced (program spec §4). walked.value.*_window carries
    -- it on for a student-facing nudge.
    return { kind = "emitted", identity = identity, verified = walked.value }
  end)

  if not ok then
    -- Rule 1 is absolute: any unexpected error still records, without identity.
    return { kind = "skipped", reason = { kind = "unexpected_error", reason = tostring(outcome) } }
  end
  return outcome
end

return M
