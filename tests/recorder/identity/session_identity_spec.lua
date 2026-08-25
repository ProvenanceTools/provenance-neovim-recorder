--- session_identity: the one place the recorder uses the student's per-course
--- PRIVATE key, and the last gate before an identity claim becomes permanent.
---
--- The module has exactly two rules, and this spec is organised around them:
---
---   1. NEVER BLOCK RECORDING. Every failure path returns `skipped` and the
---      session records without an identity. An integrity tool that silently
---      stops recording is worse than one that records under an incomplete
---      credential.
---   2. NEVER EMIT AN IDENTITY THAT DOES NOT VERIFY. `session.start` is signed
---      and hash-chained, so a broken claim in there is permanent and reads as
---      tampering during an adjudication.
---
--- Rule 1 is tested by driving every branch and asserting `skipped` plus the
--- specific reason — a test that only asserted "did not throw" would still pass
--- if the module returned `emitted` with garbage. Rule 2 is tested by walking
--- the emitted block through the real `verify_identity_chain`, the same walk the
--- analyzer performs.
local session_identity = require("provenance.recorder.identity.session_identity")
local secret_store = require("provenance.recorder.identity.secret_store")
local key_cache_mod = require("provenance.recorder.identity.key_cache")
local core_enrollment = require("provenance.core.enrollment")
local student_keys = require("provenance.core.student_keys")
local ed25519 = require("provenance.core.ed25519")

local COURSE_ID = "berkeley-cs61b"
local OTHER_COURSE_ID = "berkeley-cs61c"
local COURSE_PRIV = ("\7"):rep(32)
local ENROLL_PRIV = ("\11"):rep(32)
local STUDENT_REF = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

-- A fixed master secret so the ~6.3 ms pure-Lua derivation can be memoised
-- across the whole spec instead of paying it per example.
local MASTER_HEX = ("4a"):rep(32)
local SESSION_PUBKEY = ("9c"):rep(32)
local OTHER_SESSION_PUBKEY = ("3d"):rep(32)
local SESSION_STARTED_AT = "2026-09-10T14:00:00Z"

local function pub_hex(priv)
  return ed25519.to_hex(ed25519.public_key_of(priv))
end

local derived_cache = {}
local function derived_keypair(course_id)
  if derived_cache[course_id] == nil then
    local master = ed25519.from_hex(MASTER_HEX)
    derived_cache[course_id] = student_keys.derive_course_keypair(master, course_id)
  end
  return derived_cache[course_id]
end

--- The trust anchor. `verify_identity_chain` reads only `course_pubkey` and
--- `course_id` off it — the root signature over the cert is verified earlier,
--- during manifest activation, which is why this is a plain table here.
local function course_cert(opts)
  opts = opts or {}
  return {
    format_version = "2.0",
    course_id = opts.course_id or COURSE_ID,
    course_pubkey = opts.course_pubkey or pub_hex(COURSE_PRIV),
  }
end

local function manifest_2_0(opts)
  opts = opts or {}
  return {
    format_version = opts.format_version or "2.0",
    assignment_id = "proj2",
    semester = "fa26",
    course_id = opts.course_id or COURSE_ID,
    course_cert = opts.course_cert ~= nil and opts.course_cert or course_cert(opts),
  }
end

--- A genuinely-signed { enrollment, enrollment_cert } pair.
local function enrollment_blob(opts)
  opts = opts or {}
  local course_id = opts.course_id or COURSE_ID

  local cert = {
    format_version = "2.0",
    course_id = course_id,
    enrollment_pubkey = pub_hex(ENROLL_PRIV),
    valid_from = "2026-08-20",
    valid_until = opts.cert_valid_until or "2027-01-15",
  }
  cert.course_sig = core_enrollment.sign_enrollment_cert(cert, COURSE_PRIV)

  local token = {
    format_version = "2.0",
    student_ref = STUDENT_REF,
    course_id = course_id,
    student_pubkey = opts.student_pubkey or derived_keypair(course_id).public_key_hex,
    issued_at = opts.issued_at or "2026-09-01T00:00:00Z",
    expires_at = opts.expires_at or "2027-01-15",
  }
  token.enrollment_sig = core_enrollment.sign_enrollment_token(token, ENROLL_PRIV)

  return vim.json.encode({ enrollment = token, enrollment_cert = cert })
end

describe("session_identity.build", function()
  local tempdirs = {}

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function new_store()
    local dir = vim.fn.tempname()
    vim.fn.mkdir(dir, "p")
    table.insert(tempdirs, dir)
    return secret_store.new({ path = dir .. "/identity.json" })
  end

  --- A store holding the fixed master secret and a valid enrollment.
  local function enrolled_store(opts)
    local store = new_store()
    assert.is_true(store.import_master_secret(MASTER_HEX).ok)
    if opts == nil or opts.skip_enrollment ~= true then
      local saved = store.save_enrollment(enrollment_blob(opts))
      assert.is_true(saved.ok)
    end
    return store
  end

  local function build(overrides)
    local input = {
      manifest = manifest_2_0(),
      session_pubkey_hex = SESSION_PUBKEY,
      session_started_at = SESSION_STARTED_AT,
    }
    for k, v in pairs(overrides or {}) do
      input[k] = v
    end
    return session_identity.build(input)
  end

  -- -------------------------------------------------------------------------
  -- Rule 2 — an emitted identity always verifies
  -- -------------------------------------------------------------------------

  describe("rule 2: never emit an identity that does not verify", function()
    it("emits the three-part block for an enrolled student", function()
      local out = build({ store = enrolled_store() })

      assert.equals("emitted", out.kind)
      assert.is_table(out.identity.enrollment)
      assert.is_table(out.identity.enrollment_cert)
      assert.equals(128, #out.identity.session_pubkey_sig)
      assert.equals(COURSE_ID, out.verified.course_id)
      assert.equals(STUDENT_REF, out.verified.student_ref)
    end)

    it("the emitted block survives the analyzer's own chain walk", function()
      -- The load-bearing assertion of the whole module: not "a block was
      -- produced" but "the block verifies under the same function the analyzer
      -- will run against it years later".
      local out = build({ store = enrolled_store() })
      assert.equals("emitted", out.kind)

      local walked = core_enrollment.verify_identity_chain({
        identity = out.identity,
        session_pubkey = SESSION_PUBKEY,
        course_cert = course_cert(),
        session_started_at = SESSION_STARTED_AT,
      })
      assert.is_true(walked.ok)
    end)

    it("countersigns THIS session key and no other", function()
      -- If the binding did not actually cover session_pubkey, lifting the block
      -- onto another session would verify — which is the forgery the
      -- countersignature exists to stop.
      local out = build({ store = enrolled_store() })
      assert.equals("emitted", out.kind)

      local lifted = core_enrollment.verify_identity_chain({
        identity = out.identity,
        session_pubkey = OTHER_SESSION_PUBKEY,
        course_cert = course_cert(),
        session_started_at = SESSION_STARTED_AT,
      })
      assert.is_false(lifted.ok)
      assert.equals("invalid_session_pubkey_signature", lifted.error.kind)
    end)

    it("withholds the identity when the chain does not verify", function()
      -- A cert signed by a key the course cert does not name: every field is
      -- well-formed, so only the signature walk catches it. Writing this into a
      -- hash-chained session.start would be permanent and unrepairable.
      local store = enrolled_store()
      local out = build({
        store = store,
        manifest = manifest_2_0({ course_pubkey = pub_hex(("\31"):rep(32)) }),
      })

      assert.equals("skipped", out.kind)
      assert.equals("chain_did_not_verify", out.reason.kind)
      assert.equals("invalid_course_signature", out.reason.error.kind)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- Expiry is reported, never enforced (program spec §4)
  -- -------------------------------------------------------------------------

  it("still emits when the token has expired — expiry is never fatal", function()
    -- Same rule as an expired course_cert: silently dropping a class's identity
    -- because a course let a credential lapse punishes the student for the
    -- course's paperwork. The analyzer decides what an expired token means.
    local store = enrolled_store({ expires_at = "2026-09-02" })
    local out = build({ store = store })

    assert.equals("emitted", out.kind)
    assert.is_not_nil(out.verified.token_window)
  end)

  -- -------------------------------------------------------------------------
  -- Rule 1 — every failure records, none throws
  -- -------------------------------------------------------------------------

  describe("rule 1: never block recording", function()
    it("skips a 1.x manifest — there is no identity chain without a 2.0 anchor", function()
      local out = build({
        store = enrolled_store(),
        manifest = { format_version = "1.1", assignment_id = "proj2", semester = "fa26" },
      })
      assert.equals("skipped", out.kind)
      assert.equals("manifest_not_2_0", out.reason.kind)
    end)

    it("skips a 2.0 manifest carrying no course_cert", function()
      local m = manifest_2_0()
      m.course_cert = nil
      local out = build({ store = enrolled_store(), manifest = m })
      assert.equals("skipped", out.kind)
      assert.equals("manifest_not_2_0", out.reason.kind)
    end)

    it("skips when the manifest is not a table at all", function()
      local out = build({ store = enrolled_store(), manifest = "not-a-manifest" })
      assert.equals("skipped", out.kind)
      assert.equals("manifest_not_2_0", out.reason.kind)
    end)

    it("skips a malformed session pubkey rather than signing over it", function()
      local out = build({ store = enrolled_store(), session_pubkey_hex = "nope" })
      assert.equals("skipped", out.kind)
      assert.equals("invalid_session_pubkey", out.reason.kind)
    end)

    it("skips when no store is wired — the common case for an unenrolled user", function()
      local out = build({ store = nil })
      assert.equals("skipped", out.kind)
      assert.equals("not_enrolled", out.reason.kind)
      assert.equals(COURSE_ID, out.reason.course_id)
    end)

    it("skips when the store holds no enrollment for this course", function()
      local out = build({ store = enrolled_store({ skip_enrollment = true }) })
      assert.equals("skipped", out.kind)
      assert.equals("not_enrolled", out.reason.kind)
    end)

    it("skips when the student is enrolled in a DIFFERENT course", function()
      -- Enrollments are keyed by the manifest's course_id, so a 61C token is
      -- simply absent here — it is never offered to 61B's chain walk.
      local store = new_store()
      assert.is_true(store.import_master_secret(MASTER_HEX).ok)
      assert.is_true(store.save_enrollment(enrollment_blob({ course_id = OTHER_COURSE_ID })).ok)

      local out = build({ store = store })
      assert.equals("skipped", out.kind)
      assert.equals("not_enrolled", out.reason.kind)
    end)

    it("skips when the master secret is missing — never creates one here", function()
      -- Creating a secret at session start could not possibly derive the key an
      -- existing token names, so it would only manufacture a mismatch.
      local store = new_store()
      assert.is_true(store.save_enrollment(enrollment_blob()).ok)

      local out = build({ store = store })
      assert.equals("skipped", out.kind)
      assert.equals("master_secret_unavailable", out.reason.kind)
      assert.equals("no_master_secret", out.reason.reason)
    end)

    it("skips when the derived key is not the one the token names", function()
      -- The student moved machines and imported a different secret. Signing
      -- anyway would produce a countersignature that cannot verify.
      local store = enrolled_store({ student_pubkey = pub_hex(("\23"):rep(32)) })
      local out = build({ store = store })

      assert.equals("skipped", out.kind)
      assert.equals("student_key_mismatch", out.reason.kind)
      assert.equals(pub_hex(("\23"):rep(32)), out.reason.token_student_pubkey)
      assert.equals(derived_keypair(COURSE_ID).public_key_hex, out.reason.derived_pubkey)
    end)

    it("skips rather than propagating an unexpected error out of the store", function()
      -- Rule 1 is absolute: even a store that throws must leave the session
      -- recording. Without the pcall this example fails by raising.
      local exploding = {
        load_enrollment = function()
          error("disk on fire")
        end,
        load_master_secret = function()
          error("disk on fire")
        end,
      }
      local out = build({ store = exploding })

      assert.equals("skipped", out.kind)
      assert.equals("unexpected_error", out.reason.kind)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- Key cache seam
  -- -------------------------------------------------------------------------

  describe("key cache", function()
    it("derives through the injected cache when one is given", function()
      local calls = 0
      local cache = key_cache_mod.new({
        derive = function(master, course_id)
          calls = calls + 1
          return student_keys.derive_course_keypair(master, course_id)
        end,
      })

      local out = build({ store = enrolled_store(), key_cache = cache })
      assert.equals("emitted", out.kind)
      assert.equals(1, calls)
    end)

    it("skips without throwing when the cache cannot derive", function()
      local cache = {
        get = function()
          return nil, "derive_failed"
        end,
      }
      local out = build({ store = enrolled_store(), key_cache = cache })

      assert.equals("skipped", out.kind)
      assert.equals("master_secret_unavailable", out.reason.kind)
      assert.equals("derive_failed", out.reason.reason)
    end)

    it("derives directly when no cache is wired", function()
      local out = build({ store = enrolled_store(), key_cache = nil })
      assert.equals("emitted", out.kind)
    end)
  end)
end)
