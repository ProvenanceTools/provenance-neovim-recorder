--- Student master secret and key derivation (program spec §S2). Lua port of
--- log-core's `student-keys.ts`.
---
--- ## TWO derivations live here, and both stay
---
---  - **v2, GLOBAL (current).** `M.derive_student_keypair` — ONE key per
---    student, forever, across every course. Fixed HKDF `info`, nothing
---    user-derived. This is what the 2.1 institution-scoped credential names.
---  - **v1, PER-COURSE (legacy).** `M.derive_course_keypair` — the `info`
---    concatenates a `course_id`. Kept FOREVER: archived bundles carry 2.0
---    tokens naming per-course public keys, and those must keep verifying.
---
--- The two `info` strings differ, so the keys are unrelated and a student's
--- existing per-course keys are untouched by the move to a global key.
---
--- The rest of this docstring describes the v1 per-course derivation; the v2
--- constant and functions carry their own notes below.
---
--- One secret for a student to hold and back up; one unlinkable ed25519 keypair
--- per course derived from it:
---
---   master_secret (32 random bytes; NEVER leaves the student's machine)
---        | HKDF-SHA256, info bound to course_id
---        v
---   per-course ed25519 seed --> student per-course keypair
---        | countersigns
---        v
---   session_pubkey (the existing ephemeral session key)
---
--- ## Why derive instead of generating one key per course
---
---  - **One thing to back up.** A student who loses their key loses the ability
---    to prove authorship of their own work. Backing up one 32-byte secret is a
---    request a student can actually satisfy; a growing set of per-course keys
---    is not.
---  - **Unlinkability.** Each course sees a key derived under a different
---    `info`, so two courses comparing rosters cannot tell that two entries are
---    the same person. Correlating them requires the master secret, which never
---    leaves the machine and is never sent to any server.
---  - **Recoverability without escrow.** Re-deriving on a new machine needs only
---    the master secret. There is no server-side key store to breach, because
---    there is nothing to store.
---
--- ## THE DERIVATION IS A CROSS-LANGUAGE CONTRACT
---
--- Three recorders (TypeScript, Kotlin, Lua) must derive **byte-identical** keys
--- from the same master secret, or a signature made in one editor will not
--- verify against the public key the student's token names — and that failure
--- looks exactly like tampering. The parameters are pinned here and in the
--- `student-keys.json` vectors:
---
---   algorithm  HKDF (RFC 5869) with SHA-256
---   IKM        the 32 RAW BYTES of the master secret (not hex, not base64)
---   salt       UTF-8 bytes of "provenance-student-key-v1" — 25 bytes.
---              Deliberately NON-EMPTY: HKDF's absent-salt rule (substitute
---              HashLen zero bytes) plus HMAC's own key zero-padding make an
---              empty salt and a 32-zero-byte salt produce the SAME PRK — an
---              equivalence that is true but that no port should have to know.
---              Passing concrete bytes removes the question entirely, and means
---              this module never exercises core.hkdf's empty-salt branch.
---   info       UTF-8 bytes of ("provenance-student-key-v1:" .. course_id).
---              The trailing colon is part of the constant, and it is what makes
---              `cs61b` and `cs61b-extra` derive different keys — a port that
---              concatenated without a separator would collide on any pair of
---              ids where one is a prefix of the other. Conformance-pinned.
---   L          32 bytes
---
--- The 32-byte output IS the ed25519 secret key (seed). ed25519 accepts any 32
--- bytes as a seed, so there is no rejection sampling or retry loop — one more
--- thing three ports would otherwise have to agree on.
---
--- `course_id` enters as a **VALUE** inside a flat byte string, never as a JSON
--- object key, so the permanent no-user-derived-object-keys constraint (see
--- course_cert.lua) does not apply: UTF-8 encoding is unambiguous across all
--- three languages, whereas object-key ORDERING is not. A non-ASCII course_id is
--- therefore safe here, and a vector proves it.
---
--- ## PERFORMANCE — derive once per course, cache, never on a hot path
---
--- Derivation is one HKDF (2 HMAC-SHA256 calls) plus one ed25519 public-key
--- computation. Measured headless on an M-series laptop:
---
---   hkdf.derive alone            0.020 ms   (n=2000)
---   derive_course_key_seed       0.016 ms   (n=2000)
---   derive_course_keypair        6.28  ms   (n=20)
---
--- So the HKDF half is free and the ed25519 half is everything — the same
--- pure-Lua scalar multiplication that makes a signature verify cost ~12.8 ms
--- here. 6 ms is a visible UI hitch if it ever lands on the main loop
--- repeatedly, and it is entirely avoidable: the result is a pure function of
--- (master_secret, course_id), so it is safe to compute ONCE PER COURSE and
--- reuse for the life of the editor session.
---
--- The precedent for how to do that is `recorder/registry.lua`'s verified-root
--- cache. This module deliberately does NOT cache internally: `core/` is pure,
--- and a module-level table here would hold a student's derived PRIVATE KEY for
--- the process lifetime with no owner and no teardown path. Caching belongs to
--- the recorder layer, which has a session lifecycle to hang it on.
local hkdf = require("provenance.core.hkdf")
local ed25519 = require("provenance.core.ed25519")

local M = {}

--- Length of a student master secret, in bytes.
M.MASTER_SECRET_BYTES = 32

--- HKDF `info` prefix for the LEGACY per-course derivation. Full info is this
--- string concatenated with the `course_id`. The trailing colon is part of the
--- constant.
---
--- Kept live forever: archived bundles carry 2.0 tokens naming per-course public
--- keys, and those must keep verifying.
M.HKDF_INFO_PREFIX = "provenance-student-key-v1:"

--- HKDF `info` for the CURRENT global student key. FIXED — no `course_id`, no
--- `institution_id`, no user-derived component of any kind.
---
--- A student has ONE key, forever, across every course. Identity stopped being
--- course-scoped because a per-course key requires a per-course credential,
--- which requires a roster match, which only exists after the student's first
--- submission — while their very first session needs an identity before they do
--- any work at all. See `core/institution.lua` for the full account.
---
--- A pleasant side effect: with nothing user-derived in `info`, the encoding
--- hazard the v1 prefix has to live with is simply GONE here. Under v1 a
--- non-ASCII `course_id` encoded as `US_ASCII` rather than UTF-8 silently
--- produced a DIFFERENT key with no error — it bit provjet once, and the v1
--- conformance vectors keep a `berkeley-café` case precisely to catch a
--- recurrence. This constant is pure ASCII and constant, so there is nothing
--- left to get wrong.
---
--- There is NO trailing colon: nothing is concatenated onto it.
M.HKDF_INFO = "provenance-student-key-v2"

--- HKDF salt: the UTF-8 bytes of `provenance-student-key-v1` (25 bytes).
M.HKDF_SALT = "provenance-student-key-v1"

--- Output length of the derivation, in bytes — an ed25519 seed.
M.SEED_BYTES = 32

--- Generate a fresh 32-byte student master secret.
---
--- This is the ONLY value in the identity scheme a student must keep and back
--- up. It never leaves the machine, is never sent to a server, and is never
--- written into a log or a bundle. Losing it means losing the ability to sign as
--- yourself in every course; leaking it makes every per-course key derivable AND
--- every course identity linkable.
--- @return string  32 raw bytes
function M.generate_master_secret()
  local uv = vim.uv or vim.loop
  return uv.random(M.MASTER_SECRET_BYTES)
end

--- Derive the raw 32-byte ed25519 seed for a student's key in one course.
---
--- Pure and synchronous. RAISES on malformed input rather than returning a
--- Result, because both failure modes are programmer errors at a call site that
--- controls both arguments — an unexpected condition, not an expected one
--- (CLAUDE.md: "errors are values when expected, raised only when unexpected").
---
--- @param master_secret string  exactly M.MASTER_SECRET_BYTES RAW bytes (not hex)
--- @param course_id string      non-empty
--- @return string               32 raw bytes, usable directly as an ed25519 seed
function M.derive_course_key_seed(master_secret, course_id)
  if type(master_secret) ~= "string" or #master_secret ~= M.MASTER_SECRET_BYTES then
    error(
      "derive_course_key_seed: master_secret must be exactly "
        .. M.MASTER_SECRET_BYTES
        .. " raw bytes, got "
        .. (type(master_secret) == "string" and #master_secret or type(master_secret))
    )
  end
  if type(course_id) ~= "string" or course_id == "" then
    error("derive_course_key_seed: course_id must be a non-empty string")
  end

  return hkdf.derive(master_secret, M.HKDF_SALT, M.HKDF_INFO_PREFIX .. course_id, M.SEED_BYTES)
end

--- Derive a student's per-course ed25519 keypair from their master secret.
---
--- The private key is the seed verbatim; the public key is the ordinary ed25519
--- public key for that seed. This is the key that countersigns `session_pubkey`
--- (see enrollment.lua) and whose public half a course binds to a roster entry
--- inside an enrollment token.
---
--- ~10 ms per call in this pure-Lua port (the ed25519 half). Cache per course.
--- @param master_secret string
--- @param course_id string
--- @return table  { private_key = <32 raw bytes>, public_key_hex = <64-char hex> }
function M.derive_course_keypair(master_secret, course_id)
  local private_key = M.derive_course_key_seed(master_secret, course_id)
  return {
    private_key = private_key,
    public_key_hex = ed25519.to_hex(ed25519.public_key_of(private_key)),
  }
end

-- ---------------------------------------------------------------------------
-- The CURRENT derivation: one global student key
-- ---------------------------------------------------------------------------

--- Derive the raw 32-byte ed25519 seed for a student's single GLOBAL key.
---
--- Same master secret, same salt, same output length, same "the 32 bytes ARE the
--- ed25519 seed" rule as M.derive_course_key_seed. The ONLY difference is the
--- `info`, which is M.HKDF_INFO — fixed, ASCII, and carrying no user-derived
--- component. A student therefore has one key across every course, bound to a
--- global `student_ref` by a single credential obtained once.
---
--- Because the two `info` strings differ, the v1 per-course keys and this key
--- are unrelated: a student's existing course keys are unaffected, and archived
--- bundles keep verifying against the public keys their tokens name.
---
--- Pure and synchronous. RAISES on malformed input rather than returning a
--- Result, because that is a programmer error at a call site that controls the
--- argument — an unexpected condition, not an expected one.
---
--- @param master_secret string  exactly M.MASTER_SECRET_BYTES RAW bytes (not hex)
--- @return string               32 raw bytes, usable directly as an ed25519 seed
function M.derive_student_key_seed(master_secret)
  if type(master_secret) ~= "string" or #master_secret ~= M.MASTER_SECRET_BYTES then
    error(
      "derive_student_key_seed: master_secret must be exactly "
        .. M.MASTER_SECRET_BYTES
        .. " raw bytes, got "
        .. (type(master_secret) == "string" and #master_secret or type(master_secret))
    )
  end

  return hkdf.derive(master_secret, M.HKDF_SALT, M.HKDF_INFO, M.SEED_BYTES)
end

--- Derive a student's single GLOBAL ed25519 keypair from their master secret.
---
--- The private key is the seed verbatim; the public key is the ordinary ed25519
--- public key for that seed. This is the key that countersigns `session_pubkey`
--- (see `core/institution.lua`) and whose public half the institution binds to a
--- global `student_ref` inside a student credential.
---
--- ~10 ms per call in this pure-Lua port (the ed25519 half). Cache it — in the
--- RECORDER layer, on the `recorder/identity/key_cache.lua` precedent, never in
--- a module-level table here: `core/` is pure, and caching a derived PRIVATE KEY
--- for the process lifetime with no owner and no teardown path is strictly worse
--- than the 6 ms it saves.
--- @param master_secret string
--- @return table  { private_key = <32 raw bytes>, public_key_hex = <64-char hex> }
function M.derive_student_keypair(master_secret)
  local private_key = M.derive_student_key_seed(master_secret)
  return {
    private_key = private_key,
    public_key_hex = ed25519.to_hex(ed25519.public_key_of(private_key)),
  }
end

return M
