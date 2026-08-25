--- Enrollment certificate + enrollment token — the LEGACY course-scoped identity
--- chain, at identity `format_version` 2.0 (program spec §S2). Lua port of
--- log-core's `enrollment.ts`. Plus `M.verify_identity_chain`, which ROUTES
--- between this chain and the current institution-scoped one in
--- `institution.lua` (which owns the 2.1 walk itself — this file keeps only the
--- router and the 2.0 walk).
---
--- Structurally parallel to `course_cert.lua`: read that file first, this one
--- deliberately mirrors its shape, its Result style, and its rules.
---
--- ## THIS CHAIN IS SUPERSEDED, AND IS SUPPORTED FOREVER
---
--- Identity is no longer course-scoped. A course-scoped credential required a
--- roster match, rosters are populated by the Gradescope ingest path, and that
--- path only runs AFTER a student submits — so a student could not hold an
--- identity until after their first submission, while their first session needs
--- one before they do any work. `institution.lua` describes the replacement and
--- why it exists; new material is written there, at 2.1.
---
--- Nothing in this file may change behaviour. Every bundle already archived
--- carries a 2.0 identity block, and program spec §9 makes parsing it permanent:
--- adjudicating a case years after the fact is the entire justification for this
--- system. Treat the code below as a format contract that happens to be
--- executable.
---
--- ## The problem this layer exists to solve
---
--- An enrollment token binds a student's per-course public key to a roster
--- identity, and must be signed by the course. But the course's manifest-signing
--- key is deliberately OFFLINE — that is most of what `course_cert` buys.
--- Minting a token per student per semester is a server-side, on-demand
--- operation, so putting the course key on a server would defeat the design.
---
--- The fix is one more delegation, exactly the shape of root -> course:
---
---   root keypair          (offline; signs course certs only)
---        | signs
---        v
---   course_cert           { course_id, course_pubkey, valid_from, valid_until }
---        | authorizes
---        v
---   course keypair        (OFFLINE; signs manifests AND enrollment certs)
---        | signs
---        v
---   enrollment_cert       { format_version, course_id, enrollment_pubkey,
---                           valid_from, valid_until }
---        | authorizes
---        v
---   enrollment keypair    <-- LIVES ON THE SERVER. The only private key in the
---        | signs              whole scheme that does.
---        v
---   enrollment token      { format_version, student_ref, course_id,
---                           student_pubkey, issued_at, expires_at }
---        | authorizes
---        v
---   student per-course key (derived on the student's machine; student_keys.lua)
---        | countersigns
---        v
---   session_pubkey        (the existing ephemeral session key)
---
--- A recorder or analyzer holding only the embedded ROOT public key can walk all
--- five links offline. Nothing is fetched, and nothing from the server is
--- trusted.
---
--- **What compromise of each key costs**, which is the point of the extra layer:
--- an attacker holding the enrollment key can mint tokens for that ONE course,
--- for as long as its enrollment_cert window runs. They cannot sign a manifest,
--- cannot touch another course, and cannot outlive the cert. Recovery is a fresh
--- enrollment_cert for a new key — an offline operation the course already knows
--- how to do. Taking the course key would be far worse, which is exactly why it
--- never goes on a server.
---
--- ## `student_ref` is opaque, and is a VALUE
---
--- An opaque UUID, never a raw SID, name, or email: in a shared CS 61B repo one
--- partner can read the other's `session.start`, and the server maps
--- `student_ref` -> roster entry, so a partner sees only a UUID.
---
--- It is also never an object KEY in a signed payload. Every key in every
--- payload below is a fixed ASCII identifier chosen by us — this port's JCS
--- sorts object keys BYTEWISE while JS and Kotlin sort by UTF-16 code unit, and
--- the two agree only for ASCII (see course_cert.lua for the full rule). For the
--- same cross-port reason the signed payloads contain **no JSON arrays**, so no
--- `json.array()` tagging is needed anywhere in this module.
---
--- ## Expiry is reported, never enforced
---
--- Exactly as for `course_cert`: an out-of-window credential is NOT an error, it
--- is returned on the SUCCESS value for the caller to act on. A course letting a
--- cert lapse mid-semester must not silently stop recording for a whole class —
--- for an integrity tool that is a worse failure than recording under a stale
--- credential (program spec §4).
---
--- Every window is evaluated against **the relevant issue time**, never
--- wall-clock now, so an archived bundle still verifies years later:
---
---  - the enrollment cert's window is judged against the TOKEN's `issued_at`
---    ("was the enrollment key authorized when it minted this token");
---  - the token's window is judged against the SESSION's start time
---    ("was this student enrolled when they did this work").
---
--- ## Revocation
---
--- Not modelled, for the same reason as `course_cert`: an offline recorder
--- cannot learn about it without a network call, which recorder PRD NG2 forbids.
--- A server-side list must key on `enrollment_pubkey` and on `student_ref`, not
--- on a certificate or token identity — both travel outside any payload that
--- binds to them, so the holder chooses which copy ships. The offline mitigation
--- is short windows.
---
--- Pure: no Neovim editor APIs, no I/O. Nothing here throws — every entry point
--- is a value-returning function with pcall-wrapped crypto.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local ed25519 = require("provenance.core.ed25519")
local shapes = require("provenance.core.identity_shapes")
local institution = require("provenance.core.institution")

local M = {}

--- The version at which the identity chain exists. Both artifacts carry it
--- INSIDE their signed payloads, and verify_identity_chain gates on it before
--- walking anything.
---
--- There is no 1.x identity artifact — this layer is new — so unlike
--- `manifest.format_version` there is nothing to default and nothing to
--- grandfather. The field exists purely so a future 3.0 cannot be presented as a
--- 2.0 artifact: because it is signed, a downgraded 3.0 token fails signature
--- verification rather than being silently read under 2.0 rules. That is the S0
--- downgrade lesson, applied before it can bite rather than after.
M.FORMAT_VERSION = "2.0"

--- Fixed domain-separation tag for the session-pubkey countersignature.
M.SESSION_PUBKEY_BINDING_PURPOSE = "provenance-session-pubkey-binding-v1"

-- ---------------------------------------------------------------------------
-- Helpers
--
-- The shape and window primitives now live in `identity_shapes.lua`, shared
-- verbatim with the institution-scoped chain in `institution.lua`. Two copies of
-- "is this an ISO 8601 bound" is exactly how two ports of the same rule drift
-- apart, and this file is a port of a port. The local aliases below keep the
-- call sites in this module unchanged.
-- ---------------------------------------------------------------------------

local is_hex = shapes.is_hex
local is_plain_object = shapes.is_plain_object
local require_string = shapes.require_string
local require_hex = shapes.require_hex
local require_ordered_bounds = shapes.require_ordered_bounds
local check_window = shapes.check_window

-- ---------------------------------------------------------------------------
-- Signed payloads — the exact bytes three ports must reproduce
-- ---------------------------------------------------------------------------

--- The canonical bytes the COURSE key signs for an enrollment cert.
--- `course_sig` is excluded. JCS orders keys, so the literal order below is
--- irrelevant; the resulting key order is always:
---   course_id, enrollment_pubkey, format_version, valid_from, valid_until
--- @param cert table
--- @return string
function M.enrollment_cert_signed_payload(cert)
  return json.canonicalize({
    course_id = cert.course_id,
    enrollment_pubkey = cert.enrollment_pubkey,
    format_version = cert.format_version,
    valid_from = cert.valid_from,
    valid_until = cert.valid_until,
  })
end

--- The canonical bytes the ENROLLMENT key signs for a token.
--- `enrollment_sig` is excluded. JCS key order is always:
---   course_id, expires_at, format_version, issued_at, student_pubkey, student_ref
--- Note `student_ref` appears as a VALUE at a fixed ASCII key.
--- @param token table
--- @return string
function M.enrollment_token_signed_payload(token)
  return json.canonicalize({
    course_id = token.course_id,
    expires_at = token.expires_at,
    format_version = token.format_version,
    issued_at = token.issued_at,
    student_pubkey = token.student_pubkey,
    student_ref = token.student_ref,
  })
end

--- The canonical bytes the STUDENT per-course key signs to bind an ephemeral
--- `session_pubkey` to itself.
---
--- A bare 64-char hex string would have been the minimal thing to sign. It is
--- deliberately not what is signed:
---
---  - **Domain separation.** A signature over an unstructured blob is a
---    signature over anything that blob might also mean. The fixed `purpose` tag
---    makes this message unmistakably this message, and leaves room for the
---    student key to sign something else later without the two being confusable.
---  - **Self-describing binding.** Including `course_id` and `student_ref` means
---    the countersignature itself asserts which student, in which course,
---    adopted this session key — so verification cross-checks those against the
---    token instead of taking them on trust from elsewhere in the payload.
---
--- JCS key order is always: course_id, purpose, session_pubkey, student_ref.
--- @param binding table  { course_id, student_ref, session_pubkey }
--- @return string
function M.session_pubkey_binding_payload(binding)
  return json.canonicalize({
    course_id = binding.course_id,
    purpose = M.SESSION_PUBKEY_BINDING_PURPOSE,
    session_pubkey = binding.session_pubkey,
    student_ref = binding.student_ref,
  })
end

-- ---------------------------------------------------------------------------
-- Shape validation
-- ---------------------------------------------------------------------------

--- Validate the shape of an already-decoded enrollment cert.
---
--- Takes a value rather than text because the cert travels inline inside a
--- `session.start` payload. Unknown keys are ignored for forward compatibility,
--- which is safe: canonicalization operates on the five named fields only, so an
--- unknown key cannot silently change the signed bytes.
---
--- Does NOT check `format_version` — verify_identity_chain gates on that first
--- and reports it as a distinct error, so a version problem is never mistaken
--- for a malformed artifact.
--- @param value table
--- @return table  { ok = true, value = EnrollmentCert } | { ok = false, error = { reason, field? } }
function M.parse_enrollment_cert(value)
  if not is_plain_object(value) then
    return result.err({ reason = "not_object" })
  end

  local format_version = require_string(value, "format_version")
  if not format_version.ok then return format_version end
  local course_id = require_string(value, "course_id")
  if not course_id.ok then return course_id end
  local bounds = require_ordered_bounds(value, "valid_from", "valid_until")
  if not bounds.ok then return bounds end
  local enrollment_pubkey = require_hex(value, "enrollment_pubkey", 64)
  if not enrollment_pubkey.ok then return enrollment_pubkey end
  local course_sig = require_hex(value, "course_sig", 128)
  if not course_sig.ok then return course_sig end

  return result.ok({
    format_version = format_version.value,
    course_id = course_id.value,
    enrollment_pubkey = enrollment_pubkey.value,
    valid_from = bounds.value.lower,
    valid_until = bounds.value.upper,
    course_sig = course_sig.value,
  })
end

--- Validate the shape of an already-decoded enrollment token. Unknown keys are
--- ignored, for the same reason as parse_enrollment_cert.
--- @param value table
--- @return table  { ok = true, value = EnrollmentToken } | { ok = false, error = { reason, field? } }
function M.parse_enrollment_token(value)
  if not is_plain_object(value) then
    return result.err({ reason = "not_object" })
  end

  local format_version = require_string(value, "format_version")
  if not format_version.ok then return format_version end
  local student_ref = require_string(value, "student_ref")
  if not student_ref.ok then return student_ref end
  local course_id = require_string(value, "course_id")
  if not course_id.ok then return course_id end
  local bounds = require_ordered_bounds(value, "issued_at", "expires_at")
  if not bounds.ok then return bounds end
  local student_pubkey = require_hex(value, "student_pubkey", 64)
  if not student_pubkey.ok then return student_pubkey end
  local enrollment_sig = require_hex(value, "enrollment_sig", 128)
  if not enrollment_sig.ok then return enrollment_sig end

  return result.ok({
    format_version = format_version.value,
    student_ref = student_ref.value,
    course_id = course_id.value,
    student_pubkey = student_pubkey.value,
    issued_at = bounds.value.lower,
    expires_at = bounds.value.upper,
    enrollment_sig = enrollment_sig.value,
  })
end

-- ---------------------------------------------------------------------------
-- Signing — course/server tooling and the vector generator only. A recorder
-- never calls the first two; it only ever verifies.
-- ---------------------------------------------------------------------------

--- Sign an enrollment cert with the COURSE private key (offline operation).
--- @param cert table
--- @param course_privkey string  32-byte raw ed25519 seed
--- @return string  128-char hex signature
function M.sign_enrollment_cert(cert, course_privkey)
  return ed25519.to_hex(ed25519.sign(M.enrollment_cert_signed_payload(cert), course_privkey))
end

--- Sign an enrollment token with the ENROLLMENT private key (server-side).
--- @param token table
--- @param enrollment_privkey string  32-byte raw ed25519 seed
--- @return string  128-char hex signature
function M.sign_enrollment_token(token, enrollment_privkey)
  return ed25519.to_hex(ed25519.sign(M.enrollment_token_signed_payload(token), enrollment_privkey))
end

--- Countersign a session public key with the student's per-course private key.
--- Called by the recorder at session start — the one signing operation on this
--- path that happens on the student's machine.
--- @param binding table  { course_id, student_ref, session_pubkey }
--- @param student_privkey string  32-byte raw ed25519 seed
--- @return string  128-char hex signature
function M.sign_session_pubkey(binding, student_privkey)
  return ed25519.to_hex(ed25519.sign(M.session_pubkey_binding_payload(binding), student_privkey))
end

-- ---------------------------------------------------------------------------
-- Single-link verification
-- ---------------------------------------------------------------------------

--- Shared ed25519 verification. Every malformed input is a verification FAILURE
--- rather than an error: these values arrive from a student-editable file, so a
--- bad hex string is an expected condition, not an exceptional one.
---
--- Delegates to `identity_shapes`, so both identity families verify a detached
--- signature through exactly one implementation.
local function verify_detached(payload, sig_hex, pubkey_hex)
  return shapes.verify_detached(ed25519, payload, sig_hex, pubkey_hex)
end

--- Identity chain step 1: verify an enrollment cert against the course public
--- key that a root-verified `course_cert` vouched for.
---
--- @param cert table
--- @param course_pubkey_hex string  MUST come from an already-root-verified
---   `course_cert`. Reading it from anywhere else makes this check circular.
--- @return boolean  never throws
function M.verify_enrollment_cert(cert, course_pubkey_hex)
  if type(cert) ~= "table" then
    return false
  end
  local ok, payload = pcall(M.enrollment_cert_signed_payload, cert)
  if not ok then
    return false
  end
  return verify_detached(payload, cert.course_sig, course_pubkey_hex)
end

--- Identity chain step 2: verify an enrollment token against the enrollment
--- public key the course certified.
--- @param token table
--- @param enrollment_pubkey_hex string
--- @return boolean  never throws
function M.verify_enrollment_token(token, enrollment_pubkey_hex)
  if type(token) ~= "table" then
    return false
  end
  local ok, payload = pcall(M.enrollment_token_signed_payload, token)
  if not ok then
    return false
  end
  return verify_detached(payload, token.enrollment_sig, enrollment_pubkey_hex)
end

--- Identity chain step 4: verify that the student per-course key named by a
--- token countersigned this session's ephemeral public key.
--- @param binding table  { course_id, student_ref, session_pubkey }
--- @param sig_hex string
--- @param student_pubkey_hex string
--- @return boolean  never throws
function M.verify_session_pubkey_sig(binding, sig_hex, student_pubkey_hex)
  if type(binding) ~= "table" then
    return false
  end
  local ok, payload = pcall(M.session_pubkey_binding_payload, binding)
  if not ok then
    return false
  end
  return verify_detached(payload, sig_hex, student_pubkey_hex)
end

-- ---------------------------------------------------------------------------
-- Window checks — non-fatal, never against wall-clock now
-- ---------------------------------------------------------------------------

--- Was `token` in window at `at`?
---
--- `at` is the SESSION start time, not wall-clock now: a Fall 2026 session must
--- still read as in-window in 2030. Reuses the CertWindowStatus vocabulary, so
--- `before_valid_from` here means "before the token was issued" and
--- `after_valid_until` means "after it expired" — one status vocabulary for
--- every window in the system.
--- @param token table
--- @param at string
--- @return table  { in_window = true } | { in_window = false, reason = ... }
function M.check_token_window(token, at)
  return check_window(token.issued_at, token.expires_at, at)
end

--- Was `cert` in window at `at`? `at` is the TOKEN's `issued_at` when called
--- from verify_identity_chain — "was this enrollment key authorized when it
--- minted that token".
--- @param cert table
--- @param at string
--- @return table
function M.check_enrollment_cert_window(cert, at)
  return check_window(cert.valid_from, cert.valid_until, at)
end

-- ---------------------------------------------------------------------------
-- The full identity chain — TWO versions, one entry point
-- ---------------------------------------------------------------------------

--- Read the version an artifact DECLARES, without trusting anything else about
--- it. Safe on an unvalidated object precisely because nothing else has
--- happened yet.
local function declared_version(artifact)
  if type(artifact) ~= "table" then
    return ""
  end
  local v = artifact.format_version
  if type(v) == "string" then
    return v
  end
  return ""
end

local function shape_error(kind, inner)
  return {
    kind = kind,
    field = inner.field,
    reason = inner.reason,
  }
end

--- The LEGACY 2.0 course-scoped walk. Unchanged behaviour, kept FOREVER so an
--- archived bundle still verifies during an adjudication years from now.
---
--- Steps, in an order that is load-bearing:
---
---  0b. Both artifacts satisfy the 2.0 shape — before any signature work,
---      because a canonicalizer OMITS absent keys, so an artifact missing a
---      required field would sign and verify cleanly while carrying nothing
---      there.
---  1.  `enrollment_cert` minus `course_sig` verifies against
---      `course_cert.course_pubkey`.
---  2.  The token minus `enrollment_sig` verifies against
---      `enrollment_cert.enrollment_pubkey`.
---  3.  `token.course_id == enrollment_cert.course_id == course_cert.course_id`.
---      Not a formality: without it 61B's course key can certify an enrollment
---      key "for 61C", that key mints a 61C token, and steps 1 and 2 both pass
---      because every signature is genuine.
---  4.  `session_pubkey_sig` verifies against `token.student_pubkey` over the v1
---      binding payload for THIS exact session pubkey.
---  5.  Both validity windows — NON-FATAL, returned on the success value.
local function walk_course_chain(identity, session_pubkey, course_cert_in, session_started_at)
  if type(course_cert_in) ~= "table" then
    return result.err({ kind = "missing_trust_anchor", required = "course_cert" })
  end

  -- Step 0b — shape before signatures, for both artifacts.
  local parsed_cert = M.parse_enrollment_cert(identity.enrollment_cert)
  if not parsed_cert.ok then
    return result.err(shape_error("invalid_cert_shape", parsed_cert.error))
  end
  local parsed_token = M.parse_enrollment_token(identity.enrollment)
  if not parsed_token.ok then
    return result.err(shape_error("invalid_token_shape", parsed_token.error))
  end

  -- Verify against the VALIDATED copies, so the bytes checked here are the
  -- bytes every later reader sees.
  local cert = parsed_cert.value
  local token = parsed_token.value

  -- Step 1 — enrollment cert vs the course key the root vouched for.
  if not M.verify_enrollment_cert(cert, course_cert_in.course_pubkey) then
    return result.err({ kind = "invalid_course_signature" })
  end

  -- Step 2 — token vs the enrollment key the course certified.
  if not M.verify_enrollment_token(token, cert.enrollment_pubkey) then
    return result.err({ kind = "invalid_enrollment_signature" })
  end

  -- Step 3 — every link must name the same course.
  if token.course_id ~= cert.course_id or cert.course_id ~= course_cert_in.course_id then
    return result.err({
      kind = "course_id_mismatch",
      token_course_id = token.course_id,
      cert_course_id = cert.course_id,
      course_cert_course_id = course_cert_in.course_id,
    })
  end

  -- Step 4 — the student key adopted THIS session key.
  if not is_hex(session_pubkey, 64) then
    return result.err({ kind = "invalid_session_pubkey" })
  end
  local binding = {
    course_id = token.course_id,
    student_ref = token.student_ref,
    session_pubkey = session_pubkey,
  }
  if not M.verify_session_pubkey_sig(binding, identity.session_pubkey_sig, token.student_pubkey) then
    return result.err({ kind = "invalid_session_pubkey_signature" })
  end

  -- Step 5 — non-fatal windows, each against its own relevant issue time.
  return result.ok({
    identity_version = M.FORMAT_VERSION,
    scope = "course",
    course_id = token.course_id,
    student_ref = token.student_ref,
    student_pubkey = token.student_pubkey,
    enrollment_pubkey = cert.enrollment_pubkey,
    cert = cert,
    token = token,
    cert_window = M.check_enrollment_cert_window(cert, token.issued_at),
    token_window = M.check_token_window(token, session_started_at),
  })
end

--- THE 2.1 WALK LIVES IN `institution.lua`.
---
--- `M.walk_institution_chain` moved there, next to the 2.1 types, parsers and
--- windows it uses; the router below calls into it. It is NOT a generic walker
--- that both versions share, and must never become one: 2.0 is a frozen format
--- contract kept forever for archived bundles, so a fix to the 2.1 walk must
--- not be able to change the bytes or the error values 2.0 produces. The two
--- similar-looking bodies are load-bearing.

--- Walk the identity chain for whichever identity version the bundle declares.
---
--- ## Routing — on a SIGNED discriminator, never on field presence
---
--- Step 0 reads `identity.enrollment_cert.format_version`. That field is inside
--- the cert's signed payload in BOTH versions, at the same wire slot, so it
--- cannot be flipped without invalidating a signature and it can be found
--- without first guessing which shape is present.
---
--- Routing on which fields EXIST would have been the obvious alternative and is
--- FORBIDDEN here: the monorepo's `bundle-manifest.ts` once treated the mere
--- presence of an embedded manifest as a 2.0 claim, and that made the entire
--- legacy path unreachable. Presence is attacker-controlled and ambiguous; a
--- signed version is neither. The credential's own `format_version` must then
--- MATCH the cert's, so a legacy course-signed cert can never be paired with an
--- institution credential — each artifact would otherwise be read under rules
--- the other never agreed to.
---
--- ## `"2.0"` — legacy, COURSE-scoped. Supported forever.
---
--- Every bundle already archived carries this shape, and program spec §9 makes
--- 1.x/2.0 parsing permanent: adjudicating a case years after the fact is the
--- entire justification for this system. The walk is unchanged from the day it
--- shipped, down to the error values.
---
--- ## `"2.1"` — current, INSTITUTION-scoped. See `institution.lua`.
---
--- ## The trust anchor MUST already be verified
---
--- This function takes its anchor as a parameter and does NOT re-verify it
--- against the root key — exactly as `course_cert.verify` and
--- `institution.verify_institution_cert` take the root public key as a parameter
--- rather than knowing one. The caller obtains a `course_cert` from a successful
--- `manifest.verify_chain`, or root-verifies the `institution_cert` with
--- `institution.verify_institution_cert` before passing it. Passing an
--- unverified anchor makes every result meaningless, because an attacker who
--- supplies the anchor supplies its public key too and can then satisfy the
--- whole chain with keys of their own.
---
--- @param input table {
---   identity: { enrollment, enrollment_cert, session_pubkey_sig },
---   session_pubkey: string,       -- 64-char hex, this session's ephemeral key
---   course_cert: table|nil,       -- an ALREADY ROOT-VERIFIED course certificate.
---                                 -- Required for a 2.0 chain, ignored by 2.1.
---   institution_cert: table|nil,  -- an ALREADY ROOT-VERIFIED institution cert.
---                                 -- Required for a 2.1 chain, ignored by 2.0.
---   session_started_at: string,   -- ISO 8601; the credential's window is judged
---                                 -- against this, never wall-clock now
--- }
--- @return table
---   2.0 ok: { identity_version = "2.0", scope = "course", course_id, student_ref,
---       student_pubkey, enrollment_pubkey, cert, token, cert_window, token_window }
---   2.1 ok: { identity_version = "2.1", scope = "institution", institution_id,
---       student_ref, student_pubkey, institution_pubkey, cert, credential,
---       cert_window, token_window }
---   | { ok = false, error = { kind = "unsupported_identity_version", format_version } }
---   | { ok = false, error = { kind = "identity_version_mismatch", cert_version,
---       credential_version } }
---   | { ok = false, error = { kind = "missing_trust_anchor", required } }
---   | { ok = false, error = { kind = "invalid_cert_shape", field?, reason? } }
---   | { ok = false, error = { kind = "invalid_token_shape", field?, reason? } }
---   | { ok = false, error = { kind = "invalid_course_signature" } }            -- 2.0
---   | { ok = false, error = { kind = "invalid_enrollment_signature" } }        -- 2.0
---   | { ok = false, error = { kind = "course_id_mismatch", token_course_id,
---       cert_course_id, course_cert_course_id } }                              -- 2.0
---   | { ok = false, error = { kind = "invalid_institution_signature" } }       -- 2.1
---   | { ok = false, error = { kind = "institution_mismatch",
---       credential_institution_id, cert_institution_id, anchor_institution_id,
---       pubkey_mismatch } }                                                    -- 2.1
---   | { ok = false, error = { kind = "invalid_session_pubkey" } }
---   | { ok = false, error = { kind = "invalid_session_pubkey_signature" } }
function M.verify_identity_chain(input)
  if type(input) ~= "table" or type(input.identity) ~= "table" then
    return result.err({ kind = "invalid_cert_shape", reason = "not_object" })
  end
  local identity = input.identity

  -- Step 0 — the version gate, before anything is trusted, parsed, or verified.
  --
  -- The discriminator lives in the CERT slot: it is signed in both versions and
  -- sits at the same wire key in both, so it can be read without first knowing
  -- which shape is present. NEVER route on which fields exist.
  local cert_version = declared_version(identity.enrollment_cert)
  if cert_version ~= M.FORMAT_VERSION and cert_version ~= institution.FORMAT_VERSION then
    return result.err({
      kind = "unsupported_identity_version",
      format_version = cert_version,
    })
  end

  -- No mixing. A legacy course-signed cert paired with an institution credential
  -- would leave each artifact read under rules the other never agreed to.
  local credential_version = declared_version(identity.enrollment)
  if credential_version ~= cert_version then
    return result.err({
      kind = "identity_version_mismatch",
      cert_version = cert_version,
      credential_version = credential_version,
    })
  end

  if cert_version == institution.FORMAT_VERSION then
    return institution.walk_institution_chain(
      identity,
      input.session_pubkey,
      input.institution_cert,
      input.session_started_at
    )
  end
  return walk_course_chain(
    identity,
    input.session_pubkey,
    input.course_cert,
    input.session_started_at
  )
end

return M
