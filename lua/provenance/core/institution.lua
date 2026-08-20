--- Institution certificate + student credential — the INSTITUTION-SCOPED
--- identity chain, at identity `format_version` 2.1. Lua port of log-core's
--- `institution.ts`.
---
--- Read `enrollment.lua` first — this file is its deliberate structural
--- parallel, and that file remains live FOREVER for archived bundles.
---
--- ## Why identity stopped being course-scoped
---
--- The 2.0 chain bound a student to a COURSE: a per-course derived key, a
--- course-signed enrollment cert, a token naming a `course_id`. Minting that
--- token required a roster match, and rosters are populated by the Gradescope
--- ingest path, which only runs AFTER a student submits. So a student could not
--- obtain an identity until after their first submission — but their sessions
--- need an identity BEFORE they work, or the work carries none. That is a
--- deadlock, and course-scoping is what creates it.
---
--- What is actually needed is narrower than what 2.0 built: an identifier a
--- student obtains ONCE from our server, which lets a reader tell two students
--- on one submission apart and say which is which. Verifying course MEMBERSHIP
--- is explicitly not wanted — that is a roster question, answered later, by the
--- server, against data it owns.
---
--- ## The chain
---
---   root keypair              (offline, maintainer-held; signs course certs
---        | signs               AND institution certs — nothing else)
---        v
---   institution_cert          { format_version, institution_id,
---        | authorizes           institution_pubkey, valid_from, valid_until }
---        v                      + root_sig
---   institution keypair       <-- LIVES ON THE SERVER. The only private key
---        | signs                  that does. Signs student credentials, and
---        v                        nothing else.
---   student_credential        { format_version, institution_id, student_ref,
---        | authorizes           student_pubkey, issued_at, expires_at }
---        v                      + institution_sig
---   student keypair           (ONE per student, forever, across every course;
---        | countersigns         derived on the student's machine —
---        v                      student_keys.derive_student_keypair)
---   session_pubkey            (the existing ephemeral session key)
---
--- ONE delegation from root, not two. The 2.0 chain needed the extra
--- `course_cert -> enrollment_cert` hop purely because the course key is offline
--- and cannot mint per-student tokens on demand. The institution key is
--- certified by root directly and lives on the server, so that hop has nothing
--- left to do.
---
--- **Course keys are unaffected.** They keep signing manifests and capture
--- policy exactly as before. This change is only about identity, and the
--- identity chain deliberately does NOT anchor to whichever `course_cert` a
--- manifest carries.
---
--- ## The invariant that replaces the cross-course forgery check
---
--- The 2.0 walk compared `course_id` across three links, and that comparison was
--- not a formality: without it 61B's course key could certify an enrollment key
--- "for 61C", that key could mint a 61C token, and every signature would be
--- individually genuine. Only the comparison caught it.
---
--- The institution chain has the identical hazard one level up, and needs the
--- identical answer. Root legitimately certifies MANY institutions. An attacker
--- holding a genuinely root-certified institution key for `stanford` can mint a
--- credential whose `institution_id` says `berkeley`, ship it with their own
--- (genuine, root-signed) `stanford` cert, and every signature verifies. What
--- stops it is asserting that
---
---     credential.institution_id == institution_cert.institution_id
---                               == anchor.institution_id
---
--- and that the cert travelling in the bundle names the SAME public key as the
--- root-verified anchor. One signer's credential can then never be replayed
--- under another signer's authority. This is a MANDATORY conformance vector
--- (`chain_cases[cross_institution_forgery]` in identity.json), exactly as
--- `cross_course_forgery` is for 2.0.
---
--- ## `student_ref` is global, opaque, and always a VALUE
---
--- `student_ref` is an opaque UUID — never a raw SID, name, or email. It is now
--- GLOBAL rather than per-course: one student, one ref, one credential, every
--- course. In a shared repo one partner can read the other's `session.start`,
--- and must see only a UUID.
---
--- It is also never an object KEY in a signed payload — the permanent constraint
--- documented in `course_cert.lua`. THIS PORT's hand-rolled Lua JCS sorts object
--- keys BYTEWISE while JS and Kotlin sort by UTF-16 code unit, and the two agree
--- only for ASCII, so any user-derived key risks silently different signed bytes
--- across recorders. Every key in every payload below is a fixed ASCII
--- identifier chosen by us, and for the same cross-port reason there are no JSON
--- arrays anywhere in a signed payload — so no `json.array()` tagging is needed
--- in this module.
---
--- ## Expiry is reported, never enforced
---
--- Unchanged from 2.0. An out-of-window credential is NOT an error; it is
--- returned on the SUCCESS value for the caller to act on. An institution
--- letting a cert lapse mid-semester must not silently stop recording — for an
--- integrity tool that is a worse failure than recording under a stale
--- credential (program spec §4). And every window is judged against the RELEVANT
--- ISSUE TIME, never wall-clock now, so an archived bundle still verifies years
--- later:
---
---  - the institution cert's window is checked against the CREDENTIAL's
---    `issued_at` ("was this key authorized when it issued this credential");
---  - the credential's window is checked against the SESSION start ("did this
---    student hold a valid identity when they did this work").
---
--- ## Revocation
---
--- Not modelled here, for the same reason as `course_cert` and
--- `enrollment_cert`: an offline recorder cannot learn about it without a
--- network call, which recorder PRD NG2 forbids. A server-side list must key on
--- `institution_pubkey` and on `student_ref`, never on a certificate or
--- credential identity — both travel outside any payload that binds to them, so
--- the holder chooses which copy ships. The offline mitigation is short windows.
---
--- Pure: no Neovim editor APIs, no I/O. Nothing here throws — every entry point
--- is a value-returning function with pcall-wrapped crypto.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local ed25519 = require("provenance.core.ed25519")
local shapes = require("provenance.core.identity_shapes")

local M = {}

--- The identity `format_version` at which identity is INSTITUTION-scoped.
---
--- This value is the DISCRIMINATOR the identity chain routes on. It lives inside
--- both signed payloads, so it cannot be flipped without invalidating a
--- signature, and `verify_identity_chain` reads it before doing any signature
--- work.
---
--- Routing on a signed version — rather than on which fields happen to be
--- present — is not a stylistic preference. The monorepo's `bundle-manifest.ts`
--- once read the mere PRESENCE of an embedded manifest as a 2.0 claim, and that
--- made the entire legacy path unreachable. Presence is attacker-controlled and
--- ambiguous; a signed version is neither.
M.FORMAT_VERSION = "2.1"

--- Domain-separation tag for the 2.1 session-pubkey countersignature.
---
--- Deliberately a DIFFERENT string from the 2.0 tag. The two binding payloads
--- already differ structurally (`institution_id` vs `course_id`), so their bytes
--- could never collide — but a distinct tag makes the separation an explicit
--- property of the protocol rather than an accident of field naming, and leaves
--- the 2.0 tag meaning exactly one thing forever.
M.SESSION_BINDING_PURPOSE = "provenance-session-pubkey-binding-v2"

-- ---------------------------------------------------------------------------
-- Signed payloads — the exact bytes three ports must reproduce
-- ---------------------------------------------------------------------------

--- The canonical bytes the ROOT key signs for an institution cert.
---
--- `root_sig` is excluded; the five remaining fields are canonicalized. JCS
--- orders keys, so the literal order below is irrelevant to the output — the
--- resulting key order is always:
---   format_version, institution_id, institution_pubkey, valid_from, valid_until
--- @param cert table
--- @return string
function M.institution_cert_signed_payload(cert)
  return json.canonicalize({
    format_version = cert.format_version,
    institution_id = cert.institution_id,
    institution_pubkey = cert.institution_pubkey,
    valid_from = cert.valid_from,
    valid_until = cert.valid_until,
  })
end

--- The canonical bytes the INSTITUTION key signs for a student credential.
---
--- `institution_sig` is excluded; the six remaining fields are canonicalized.
--- The resulting JCS key order is always:
---   expires_at, format_version, institution_id, issued_at, student_pubkey,
---   student_ref
---
--- Note `student_ref` appears as a VALUE at a fixed ASCII key — never promoted
--- to a key itself. See the module docstring.
--- @param credential table
--- @return string
function M.student_credential_signed_payload(credential)
  return json.canonicalize({
    expires_at = credential.expires_at,
    format_version = credential.format_version,
    institution_id = credential.institution_id,
    issued_at = credential.issued_at,
    student_pubkey = credential.student_pubkey,
    student_ref = credential.student_ref,
  })
end

--- The canonical bytes the STUDENT key signs to bind an ephemeral
--- `session_pubkey` to itself.
---
--- A bare 64-char hex string would have been the minimal thing to sign. It is
--- not what is signed, for the same two reasons as in 2.0:
---
---  - **Domain separation.** A signature over an unstructured blob is a
---    signature over anything that blob might also mean. The fixed `purpose` tag
---    makes this message unmistakably this message.
---  - **Self-describing binding.** Including `institution_id` and `student_ref`
---    means the countersignature itself asserts WHICH student, at WHICH
---    institution, adopted this session key, rather than taking either on trust
---    from elsewhere in the payload.
---
--- JCS key order is always: institution_id, purpose, session_pubkey, student_ref.
--- @param binding table  { institution_id, student_ref, session_pubkey }
--- @return string
function M.session_binding_payload(binding)
  return json.canonicalize({
    institution_id = binding.institution_id,
    purpose = M.SESSION_BINDING_PURPOSE,
    session_pubkey = binding.session_pubkey,
    student_ref = binding.student_ref,
  })
end

-- ---------------------------------------------------------------------------
-- Shape validation — always before signature work
-- ---------------------------------------------------------------------------

--- Validate the shape of an already-decoded institution cert.
---
--- Takes a value rather than text because the cert travels inline inside a
--- `session.start` payload. Unknown keys are ignored for forward compatibility,
--- which is safe: canonicalization operates on the five named fields only, so an
--- unknown key cannot silently change the signed bytes.
---
--- Does NOT check `format_version` against M.FORMAT_VERSION — the chain gates on
--- that first and reports it as a distinct error, so a version problem is never
--- mistaken for a malformed artifact.
--- @param value any
--- @return table  { ok = true, value = InstitutionCert } | { ok = false, error = { reason, field? } }
function M.parse_institution_cert(value)
  if not shapes.is_plain_object(value) then
    return result.err({ reason = "not_object" })
  end

  local format_version = shapes.require_string(value, "format_version")
  if not format_version.ok then return format_version end
  local institution_id = shapes.require_string(value, "institution_id")
  if not institution_id.ok then return institution_id end
  local bounds = shapes.require_ordered_bounds(value, "valid_from", "valid_until")
  if not bounds.ok then return bounds end
  local institution_pubkey = shapes.require_hex(value, "institution_pubkey", shapes.HEX_64)
  if not institution_pubkey.ok then return institution_pubkey end
  local root_sig = shapes.require_hex(value, "root_sig", shapes.HEX_128)
  if not root_sig.ok then return root_sig end

  return result.ok({
    format_version = format_version.value,
    institution_id = institution_id.value,
    institution_pubkey = institution_pubkey.value,
    valid_from = bounds.value.lower,
    valid_until = bounds.value.upper,
    root_sig = root_sig.value,
  })
end

--- Validate the shape of an already-decoded student credential. Unknown keys are
--- ignored, for the same reason as M.parse_institution_cert.
--- @param value any
--- @return table  { ok = true, value = StudentCredential } | { ok = false, error = { reason, field? } }
function M.parse_student_credential(value)
  if not shapes.is_plain_object(value) then
    return result.err({ reason = "not_object" })
  end

  local format_version = shapes.require_string(value, "format_version")
  if not format_version.ok then return format_version end
  local institution_id = shapes.require_string(value, "institution_id")
  if not institution_id.ok then return institution_id end
  local student_ref = shapes.require_string(value, "student_ref")
  if not student_ref.ok then return student_ref end
  local bounds = shapes.require_ordered_bounds(value, "issued_at", "expires_at")
  if not bounds.ok then return bounds end
  local student_pubkey = shapes.require_hex(value, "student_pubkey", shapes.HEX_64)
  if not student_pubkey.ok then return student_pubkey end
  local institution_sig = shapes.require_hex(value, "institution_sig", shapes.HEX_128)
  if not institution_sig.ok then return institution_sig end

  return result.ok({
    format_version = format_version.value,
    institution_id = institution_id.value,
    student_ref = student_ref.value,
    student_pubkey = student_pubkey.value,
    issued_at = bounds.value.lower,
    expires_at = bounds.value.upper,
    institution_sig = institution_sig.value,
  })
end

-- ---------------------------------------------------------------------------
-- Signing — maintainer/server tooling and the vector generator only.
-- A recorder never calls the first two; it only ever verifies.
-- ---------------------------------------------------------------------------

--- Sign an institution cert with the ROOT private key (offline operation).
--- @param cert table
--- @param root_privkey string  32-byte raw ed25519 seed
--- @return string  128-char hex signature
function M.sign_institution_cert(cert, root_privkey)
  return ed25519.to_hex(ed25519.sign(M.institution_cert_signed_payload(cert), root_privkey))
end

--- Sign a student credential with the INSTITUTION private key (server-side).
--- @param credential table
--- @param institution_privkey string  32-byte raw ed25519 seed
--- @return string  128-char hex signature
function M.sign_student_credential(credential, institution_privkey)
  return ed25519.to_hex(
    ed25519.sign(M.student_credential_signed_payload(credential), institution_privkey)
  )
end

--- Countersign a session public key with the student's long-lived private key.
--- Called by the recorder at session start — the one signing operation on this
--- path that happens on the student's machine.
--- @param binding table  { institution_id, student_ref, session_pubkey }
--- @param student_privkey string  32-byte raw ed25519 seed
--- @return string  128-char hex signature
function M.sign_session_binding(binding, student_privkey)
  return ed25519.to_hex(ed25519.sign(M.session_binding_payload(binding), student_privkey))
end

-- ---------------------------------------------------------------------------
-- Single-link verification
-- ---------------------------------------------------------------------------

--- Verify an institution cert against the ROOT public key.
---
--- This is the call that turns a cert travelling in a student-editable bundle
--- into a TRUST ANCHOR. `verify_identity_chain` does NOT do it — exactly as it
--- does not re-verify `course_cert`, and exactly as `course_cert.verify` takes
--- the root key as a parameter rather than knowing one. The caller performs it
--- and passes the result in; skipping it makes the whole chain meaningless,
--- because an attacker who supplies the cert supplies `institution_pubkey` too.
---
--- @param cert table
--- @param root_pubkey_hex string  the recorder's embedded ROOT_PUBLIC_KEY_HEX, or
---   the analyzer's configured root key. NEVER read from the bundle.
--- @return boolean  never throws
function M.verify_institution_cert(cert, root_pubkey_hex)
  if type(cert) ~= "table" then
    return false
  end
  local ok, payload = pcall(M.institution_cert_signed_payload, cert)
  if not ok then
    return false
  end
  return shapes.verify_detached(ed25519, payload, cert.root_sig, root_pubkey_hex)
end

--- Verify a student credential against the institution public key the root
--- certified.
---
--- @param credential table
--- @param institution_pubkey_hex string  MUST come from an already-root-verified
---   `institution_cert`. Reading it from the credential's own travelling
---   companion makes this check circular.
--- @return boolean  never throws
function M.verify_student_credential(credential, institution_pubkey_hex)
  if type(credential) ~= "table" then
    return false
  end
  local ok, payload = pcall(M.student_credential_signed_payload, credential)
  if not ok then
    return false
  end
  return shapes.verify_detached(
    ed25519,
    payload,
    credential.institution_sig,
    institution_pubkey_hex
  )
end

--- Verify that the student key named by a credential countersigned this
--- session's ephemeral public key.
--- @param binding table  { institution_id, student_ref, session_pubkey }
--- @param sig_hex any
--- @param student_pubkey_hex any
--- @return boolean  never throws
function M.verify_session_binding(binding, sig_hex, student_pubkey_hex)
  if type(binding) ~= "table" then
    return false
  end
  local ok, payload = pcall(M.session_binding_payload, binding)
  if not ok then
    return false
  end
  return shapes.verify_detached(ed25519, payload, sig_hex, student_pubkey_hex)
end

-- ---------------------------------------------------------------------------
-- Window checks — non-fatal, never against wall-clock now
-- ---------------------------------------------------------------------------

--- Was `credential` in window at `at`?
---
--- `at` is the SESSION start time, not wall-clock now: a Fall 2026 session must
--- still read as in-window in 2031. Reuses the CertWindowStatus vocabulary, so
--- one status vocabulary covers every window in the system.
--- @param credential table
--- @param at string
--- @return table
function M.check_credential_window(credential, at)
  return shapes.check_window(credential.issued_at, credential.expires_at, at)
end

--- Was `cert` in window at `at`? `at` is the CREDENTIAL's `issued_at` when
--- called from the identity chain — "was this institution key authorized when it
--- issued that credential".
--- @param cert table
--- @param at string
--- @return table
function M.check_institution_cert_window(cert, at)
  return shapes.check_window(cert.valid_from, cert.valid_until, at)
end

return M
