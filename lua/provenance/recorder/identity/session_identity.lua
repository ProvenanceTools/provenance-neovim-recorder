--- Build the `session.start.identity` block (program spec §5, §5a step 5).
---
--- This is the one place on the recorder where the student's PRIVATE key is
--- used. It derives that key from the master secret, countersigns this session's
--- ephemeral `session_pubkey`, and assembles
--- `{ enrollment, enrollment_cert, session_pubkey_sig }`.
---
--- ## Two identity families, and which one wins
---
--- - **2.1, INSTITUTION-scoped (current).** Anchored to the recorder's embedded
---   ROOT public key, using the student's single GLOBAL key. Does not consult the
---   manifest at all, so it works in any workspace — including one whose manifest
---   is 1.x.
--- - **2.0, COURSE-scoped (legacy).** Anchored to the manifest's root-verified
---   `course_cert`, using a per-course derived key. Kept forever: a token a
---   student already holds must keep working.
---
--- **If a 2.1 credential is stored it DECIDES, with no fallback to 2.0.** The two
--- families attribute to different `student_ref`s — 2.0's is per-course, 2.1's is
--- global — so quietly falling back would file the session under a different
--- contributor than the student believes, and would hide the 2.1 problem that
--- caused it. An integrity tool must not quietly change who it says did the work.
--- Not blocking recording is preserved either way: a failed 2.1 path skips the
--- identity block, exactly as every other failure here does.
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
--- assembled block is walked with `verify_identity_chain` against an
--- ALREADY-ROOT-VERIFIED anchor — the manifest's `course_cert` at 2.0, the
--- root-verified `institution_cert` at 2.1 — the same walk the analyzer will
--- perform. A block that fails is dropped rather than written, because
--- `session.start` is signed and hash-chained: a broken claim in there is
--- permanent, unrepairable, and looks exactly like tampering during an
--- adjudication.
---
--- ## No network. Ever.
---
--- Recorder PRD NG2. Nothing here fetches. The enrollment token arrives by PASTE
--- (`commands/enrollment.lua`) and everything else is derived locally, so the
--- whole identity path works on a plane.
local core_enrollment = require("provenance.core.enrollment")
local core_institution = require("provenance.core.institution")
local core_manifest = require("provenance.core.manifest")
local trust_keys = require("provenance.trust_keys")

local M = {}

local function is_hex_64(v)
  return type(v) == "string" and #v == 64 and v:match("^[0-9a-f]+$") ~= nil
end

--- The 2.1 INSTITUTION-scoped path.
---
--- Structurally the twin of the 2.0 path below, with three differences that all
--- follow from identity no longer being course-scoped:
---
---  - **The manifest is not consulted at all.** A 2.1 credential names no course,
---    so there is nothing to match against `manifest.course_id`, and the trust
---    anchor is the recorder's embedded ROOT key rather than the manifest's
---    `course_cert`. A student with a 2.1 credential therefore gets an identity
---    even in a 1.x workspace — which is the point: the 2.0 design could not
---    produce an identity before the student's first submission.
---  - **The student key is the single GLOBAL one**, not a per-course derivation.
---  - **The anchor is root-verified HERE, by us.** `verify_identity_chain` does
---    not do it, deliberately — it takes the anchor as a parameter exactly as the
---    2.0 walk takes an already-verified `course_cert`. Passing the stored cert
---    unverified would make the entire walk meaningless, because whoever supplies
---    the cert supplies its `institution_pubkey` too.
--- @return table  { kind = "emitted", ... } | { kind = "skipped", reason = ... }
local function build_institution_identity(input, stored)
  local root_pubkey_hex = input.root_pubkey_hex or trust_keys.ROOT_PUBLIC_KEY_HEX
  if not is_hex_64(root_pubkey_hex) then
    -- A build/packaging problem, not a student one.
    return { kind = "skipped", reason = { kind = "no_root_public_key" } }
  end

  -- Turn the stored cert into a TRUST ANCHOR, or refuse to proceed.
  if not core_institution.verify_institution_cert(stored.enrollment_cert, root_pubkey_hex) then
    return { kind = "skipped", reason = { kind = "institution_cert_not_root_signed" } }
  end

  -- The student key. LOADED, never created: a freshly generated secret could not
  -- possibly derive the key an existing credential names.
  local master = input.store.load_master_secret()
  if not master.ok then
    return {
      kind = "skipped",
      reason = { kind = "master_secret_unavailable", reason = master.error.kind },
    }
  end

  local keypair, derive_err
  if input.key_cache ~= nil then
    keypair, derive_err = input.key_cache.get_global(master.value)
  else
    local student_keys = require("provenance.core.student_keys")
    local derive_ok, kp = pcall(student_keys.derive_student_keypair, master.value)
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
    -- Normally a credential obtained before the student moved machines and
    -- imported a different secret. Signing anyway would produce a
    -- countersignature that cannot verify.
    return {
      kind = "skipped",
      reason = {
        kind = "credential_key_mismatch",
        credential_student_pubkey = stored.enrollment.student_pubkey,
        derived_pubkey = keypair.public_key_hex,
      },
    }
  end

  -- Countersign this session's ephemeral key under the v2 binding payload. Its
  -- `purpose` tag differs from 2.0's, so a countersignature can never be
  -- replayed across versions.
  local session_pubkey_sig = core_institution.sign_session_binding({
    institution_id = stored.enrollment.institution_id,
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
    institution_cert = stored.enrollment_cert,
    session_started_at = input.session_started_at,
  })
  if not walked.ok then
    return { kind = "skipped", reason = { kind = "chain_did_not_verify", error = walked.error } }
  end

  -- Out-of-window is deliberately NOT a reason to withhold: expiry is reported,
  -- never enforced (program spec §4).
  return { kind = "emitted", identity = identity, verified = walked.value }
end

--- @param input table {
---   manifest: table            -- the ALREADY-VERIFIED manifest for this root.
---                             -- Its course_cert is the 2.0 trust anchor, so
---                             -- passing an unverified manifest makes the 2.0
---                             -- verification below meaningless. Not consulted
---                             -- at all on the 2.1 path.
---   session_pubkey_hex: string -- this session's ephemeral public key
---   session_started_at: string -- ISO 8601; the credential's window is judged
---                             -- against this, never wall-clock now, so an
---                             -- archived bundle still reads correctly years later
---   store: table               -- a recorder.identity.secret_store instance
---   key_cache: table|nil       -- a recorder.identity.key_cache instance
---   root_pubkey_hex: string|nil -- injection seam for tests. Production uses the
---                             -- recorder's embedded trust_keys.ROOT_PUBLIC_KEY_HEX,
---                             -- which is the 2.1 trust anchor.
--- }
--- @return table
---   { kind = "emitted", identity = {...}, verified = {...} }
---   | { kind = "skipped", reason = { kind = ..., ... } }
function M.build(input)
  local ok, outcome = pcall(function()
    local manifest = input.manifest
    local store = input.store

    if not is_hex_64(input.session_pubkey_hex) then
      return { kind = "skipped", reason = { kind = "invalid_session_pubkey" } }
    end

    -- PRECEDENCE: 2.1 first, and if a 2.1 credential is stored it DECIDES.
    -- There is deliberately NO fallback to 2.0 if the 2.1 path then fails — see
    -- the precedence note in this module's header.
    if type(store) == "table" then
      local credential = store.load_student_credential ~= nil
        and store.load_student_credential()
        or nil
      if type(credential) == "table" then
        return build_institution_identity(input, credential)
      end
    end

    -- --- 2.0, LEGACY. Reached only when no 2.1 credential is stored.
    -- Anchor: there is no 2.0 identity chain without a course cert to anchor it.
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
