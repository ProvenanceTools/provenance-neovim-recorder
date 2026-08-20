--- The recorder layer of the INSTITUTION-scoped 2.1 identity chain: the secret
--- store's credential slot and version-routed importer, the global key cache,
--- and `session_identity`'s 2.1 path.
---
--- The two rules that govern `session_identity` are unchanged and are what this
--- spec is organised around:
---
---   1. NEVER BLOCK RECORDING. Every failure path returns `skipped` and the
---      session records without an identity. An integrity tool that silently
---      stops recording is worse than one that records under an incomplete
---      credential.
---   2. NEVER EMIT AN IDENTITY THAT DOES NOT VERIFY. `session.start` is signed
---      and hash-chained, so a broken claim in there is permanent and reads as
---      tampering during an adjudication.
---
--- Rule 2 is tested by walking every emitted block through the real
--- `verify_identity_chain` — the same walk the analyzer performs — rather than
--- by asserting that a block was produced.
local session_identity = require("provenance.recorder.identity.session_identity")
local secret_store = require("provenance.recorder.identity.secret_store")
local key_cache_mod = require("provenance.recorder.identity.key_cache")
local core_enrollment = require("provenance.core.enrollment")
local core_institution = require("provenance.core.institution")
local student_keys = require("provenance.core.student_keys")
local ed25519 = require("provenance.core.ed25519")

local INSTITUTION_ID = "berkeley"
local OTHER_INSTITUTION_ID = "stanford"
local STUDENT_REF = "9c8e1a70-2f2b-4c55-8f1e-6b4a0d9c7e21"

local ROOT_PRIV = ("\20"):rep(32)
local WRONG_ROOT_PRIV = ("\21"):rep(32)
local INSTITUTION_PRIV = ("\22"):rep(32)
local OTHER_INSTITUTION_PRIV = ("\23"):rep(32)

-- Legacy 2.0 material, for the precedence cases.
local COURSE_ID = "berkeley-cs61b"
local COURSE_PRIV = ("\7"):rep(32)
local ENROLL_PRIV = ("\11"):rep(32)
local COURSE_STUDENT_REF = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

-- A fixed master secret, so the ~6.3 ms pure-Lua derivation is paid once for the
-- whole spec rather than once per example.
local MASTER_HEX = ("4a"):rep(32)
local OTHER_MASTER_HEX = ("7b"):rep(32)
local SESSION_PUBKEY = ("9c"):rep(32)
local SESSION_STARTED_AT = "2026-09-10T14:00:00Z"

local function pub_hex(priv)
  return ed25519.to_hex(ed25519.public_key_of(priv))
end

local global_cache = {}
local function global_keypair(master_hex)
  if global_cache[master_hex] == nil then
    global_cache[master_hex] =
      student_keys.derive_student_keypair(ed25519.from_hex(master_hex))
  end
  return global_cache[master_hex]
end

local course_cache = {}
local function course_keypair(course_id)
  if course_cache[course_id] == nil then
    course_cache[course_id] =
      student_keys.derive_course_keypair(ed25519.from_hex(MASTER_HEX), course_id)
  end
  return course_cache[course_id]
end

--- A genuinely root-signed institution cert.
local function institution_cert(opts)
  opts = opts or {}
  local cert = {
    format_version = "2.1",
    institution_id = opts.institution_id or INSTITUTION_ID,
    institution_pubkey = opts.institution_pubkey or pub_hex(INSTITUTION_PRIV),
    valid_from = opts.valid_from or "2026-08-20",
    valid_until = opts.valid_until or "2027-01-15",
  }
  cert.root_sig = core_institution.sign_institution_cert(cert, opts.root_priv or ROOT_PRIV)
  return cert
end

--- A genuinely institution-signed student credential.
local function student_credential(opts)
  opts = opts or {}
  local credential = {
    format_version = "2.1",
    institution_id = opts.institution_id or INSTITUTION_ID,
    student_ref = opts.student_ref or STUDENT_REF,
    student_pubkey = opts.student_pubkey or global_keypair(MASTER_HEX).public_key_hex,
    issued_at = opts.issued_at or "2026-09-01T00:00:00Z",
    expires_at = opts.expires_at or "2027-01-15",
  }
  credential.institution_sig = core_institution.sign_student_credential(
    credential,
    opts.institution_priv or INSTITUTION_PRIV
  )
  return credential
end

local function credential_blob(opts)
  opts = opts or {}
  return vim.json.encode({
    enrollment = opts.credential or student_credential(opts),
    enrollment_cert = opts.cert or institution_cert(opts),
  })
end

--- A genuinely-signed LEGACY 2.0 { enrollment, enrollment_cert } pair.
local function enrollment_blob()
  local cert = {
    format_version = "2.0",
    course_id = COURSE_ID,
    enrollment_pubkey = pub_hex(ENROLL_PRIV),
    valid_from = "2026-08-20",
    valid_until = "2027-01-15",
  }
  cert.course_sig = core_enrollment.sign_enrollment_cert(cert, COURSE_PRIV)

  local token = {
    format_version = "2.0",
    student_ref = COURSE_STUDENT_REF,
    course_id = COURSE_ID,
    student_pubkey = course_keypair(COURSE_ID).public_key_hex,
    issued_at = "2026-09-01T00:00:00Z",
    expires_at = "2027-01-15",
  }
  token.enrollment_sig = core_enrollment.sign_enrollment_token(token, ENROLL_PRIV)

  return vim.json.encode({ enrollment = token, enrollment_cert = cert })
end

local function manifest_2_0()
  return {
    format_version = "2.0",
    assignment_id = "proj2",
    semester = "fa26",
    course_id = COURSE_ID,
    course_cert = {
      format_version = "2.0",
      course_id = COURSE_ID,
      course_pubkey = pub_hex(COURSE_PRIV),
    },
  }
end

describe("identity 2.1 (institution-scoped) — the recorder layer", function()
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

  local function credentialed_store(opts)
    local store = new_store()
    assert.is_true(store.import_master_secret(MASTER_HEX).ok)
    assert.is_true(store.save_student_credential(credential_blob(opts)).ok)
    return store
  end

  local function build(overrides)
    local input = {
      manifest = manifest_2_0(),
      session_pubkey_hex = SESSION_PUBKEY,
      session_started_at = SESSION_STARTED_AT,
      root_pubkey_hex = pub_hex(ROOT_PRIV),
    }
    for k, v in pairs(overrides or {}) do
      input[k] = v
    end
    return session_identity.build(input)
  end

  -- -------------------------------------------------------------------------
  -- secret_store: the credential slot
  -- -------------------------------------------------------------------------

  describe("secret_store credential slot", function()
    it("stores ONE credential with no course component, and reads it back", function()
      -- A 2.1 credential names no course, so there is nothing to key by. The
      -- storage shape is where the 2.0 -> 2.1 change becomes visible.
      local store = new_store()
      local saved = store.save_student_credential(credential_blob())
      assert.is_true(saved.ok)
      assert.equals(INSTITUTION_ID, saved.value.institution_id)
      assert.equals(STUDENT_REF, saved.value.student_ref)

      local loaded = store.load_student_credential()
      assert.is_table(loaded)
      assert.equals(STUDENT_REF, loaded.enrollment.student_ref)
      assert.equals(INSTITUTION_ID, loaded.enrollment_cert.institution_id)
    end)

    it("a second credential REPLACES the first — there is only ever one", function()
      local store = new_store()
      assert.is_true(store.save_student_credential(credential_blob()).ok)
      assert.is_true(store.save_student_credential(
        credential_blob({ student_ref = "11111111-2222-4333-8444-555555555555" })
      ).ok)
      assert.equals(
        "11111111-2222-4333-8444-555555555555",
        store.load_student_credential().enrollment.student_ref
      )
    end)

    it("clear_student_credential never touches the master secret", function()
      local store = credentialed_store()
      store.clear_student_credential()
      assert.is_nil(store.load_student_credential())
      assert.is_true(store.load_master_secret().ok)
    end)

    it("refuses a mixed paste: credential and cert naming different institutions", function()
      -- Caught while the student is standing there to fix it. This is NOT the
      -- cross-institution forgery check — that needs the root-verified anchor,
      -- which import time does not have.
      local store = new_store()
      local bad = store.save_student_credential(vim.json.encode({
        enrollment = student_credential({ institution_id = OTHER_INSTITUTION_ID }),
        enrollment_cert = institution_cert(),
      }))
      assert.is_false(bad.ok)
      assert.equals("institution_id_mismatch", bad.error.kind)
      assert.is_nil(store.load_student_credential())
    end)

    it("gates on the version BEFORE the shape, on both slots", function()
      local store = new_store()
      for _, case in ipairs({
        { field = "enrollment_cert", artifact = "cert" },
        { field = "enrollment", artifact = "credential" },
      }) do
        local blob = {
          enrollment = student_credential(),
          enrollment_cert = institution_cert(),
        }
        blob[case.field].format_version = "3.0"
        local res = store.save_student_credential(vim.json.encode(blob))
        assert.is_false(res.ok)
        assert.equals("unsupported_format_version", res.error.kind)
        assert.equals(case.artifact, res.error.artifact)
        assert.equals("3.0", res.error.format_version)
      end
    end)

    it("returns nil for every read failure, so a session-start caller records anyway", function()
      local store = new_store()
      assert.is_nil(store.load_student_credential())
    end)
  end)

  -- -------------------------------------------------------------------------
  -- secret_store: the ONE importer, routed on the SIGNED version
  -- -------------------------------------------------------------------------

  describe("save_identity_artifact routes on the SIGNED version", function()
    it("a 2.1 paste lands in the credential slot", function()
      local store = new_store()
      local res = store.save_identity_artifact(credential_blob())
      assert.is_true(res.ok)
      assert.equals("2.1", res.value.identity_version)
      assert.equals(INSTITUTION_ID, res.value.institution_id)
      assert.equals(
        global_keypair(MASTER_HEX).public_key_hex,
        res.value.student_pubkey
      )
      assert.is_table(store.load_student_credential())
    end)

    it("a 2.0 paste STILL imports, into the per-course slot", function()
      -- 2.0 minting is retired; 2.0 handling is not. A token a student already
      -- holds must keep working.
      local store = new_store()
      local res = store.save_identity_artifact(enrollment_blob())
      assert.is_true(res.ok)
      assert.equals("2.0", res.value.identity_version)
      assert.equals(COURSE_ID, res.value.course_id)
      assert.is_table(store.load_enrollment(COURSE_ID))
      assert.is_nil(store.load_student_credential())
    end)

    it("routes on the cert's format_version, NOT on which fields are present", function()
      -- The two families use the SAME two wire slots, so field presence says
      -- nothing about which version this is. Here the cert declares 2.0 while
      -- carrying institution-shaped fields: the signed version decides, and the
      -- 2.0 importer then rejects it on shape rather than storing a credential.
      local store = new_store()
      local cert = institution_cert()
      cert.format_version = "2.0"
      local credential = student_credential()
      credential.format_version = "2.0"
      local res = store.save_identity_artifact(
        vim.json.encode({ enrollment = credential, enrollment_cert = cert })
      )
      assert.is_false(res.ok)
      assert.equals("legacy_2_0", res.error.kind, "must have been routed to the 2.0 importer")
      assert.is_nil(store.load_student_credential())
    end)

    it("a version that is neither 2.0 nor 2.1 is refused outright", function()
      local store = new_store()
      local res = store.save_identity_artifact(
        credential_blob({ cert = (function()
          local c = institution_cert()
          c.format_version = "3.0"
          return c
        end)() })
      )
      assert.is_false(res.ok)
      assert.equals("unsupported_identity_version", res.error.kind)
      assert.equals("3.0", res.error.format_version)
    end)

    it("garbage is a value, not a raise", function()
      local store = new_store()
      local res = store.save_identity_artifact("{not json")
      assert.is_false(res.ok)
      assert.equals("invalid_json", res.error.kind)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- key_cache: the global key
  -- -------------------------------------------------------------------------

  describe("key_cache.get_global", function()
    it("derives once and reuses, keyed on the master-secret fingerprint", function()
      local calls = 0
      local cache = key_cache_mod.new({
        derive_global = function(master)
          calls = calls + 1
          return { private_key = master, public_key_hex = ("a"):rep(64) }
        end,
      })
      local master = ed25519.from_hex(MASTER_HEX)
      assert.equals(("a"):rep(64), cache.get_global(master).public_key_hex)
      assert.equals(("a"):rep(64), cache.get_global(master).public_key_hex)
      assert.equals(1, calls)

      -- A DIFFERENT master secret must not be served the first one's key: that
      -- would silently produce a countersignature the credential cannot verify.
      cache.get_global(ed25519.from_hex(OTHER_MASTER_HEX))
      assert.equals(2, calls)
    end)

    it("global and per-course entries never collide", function()
      -- The two derivations use different HKDF info and produce DIFFERENT keys
      -- from the same secret. A collision would hand a caller the wrong private
      -- key.
      local cache = key_cache_mod.new({
        derive_global = function() return { public_key_hex = "GLOBAL" } end,
        derive = function() return { public_key_hex = "COURSE" } end,
      })
      local master = ed25519.from_hex(MASTER_HEX)
      assert.equals("GLOBAL", cache.get_global(master).public_key_hex)
      assert.equals("COURSE", cache.get(master, COURSE_ID).public_key_hex)
      assert.equals("GLOBAL", cache.get_global(master).public_key_hex)
      assert.equals(2, cache._size())
    end)

    it("dispose drops the global key but the cache still answers", function()
      -- No private key may outlive teardown; callers must keep working.
      local cache = key_cache_mod.new({
        derive_global = function() return { public_key_hex = "GLOBAL" } end,
      })
      local master = ed25519.from_hex(MASTER_HEX)
      cache.get_global(master)
      assert.equals(1, cache._size())
      cache.dispose()
      assert.equals(0, cache._size())
      assert.equals("GLOBAL", cache.get_global(master).public_key_hex)
      assert.equals(0, cache._size())
    end)

    it("a derive failure is a value, not a raise", function()
      local cache = key_cache_mod.new({
        derive_global = function() error("boom") end,
      })
      local keypair, e = cache.get_global(ed25519.from_hex(MASTER_HEX))
      assert.is_nil(keypair)
      assert.is_not_nil(e)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- session_identity — rule 2: never emit an identity that does not verify
  -- -------------------------------------------------------------------------

  describe("rule 2: never emit an identity that does not verify", function()
    it("emits the three-part block for a credentialed student", function()
      local out = build({ store = credentialed_store() })

      assert.equals("emitted", out.kind)
      assert.equals(128, #out.identity.session_pubkey_sig)
      assert.equals("2.1", out.verified.identity_version)
      assert.equals("institution", out.verified.scope)
      assert.equals(INSTITUTION_ID, out.verified.institution_id)
      assert.equals(STUDENT_REF, out.verified.student_ref)
    end)

    it("the emitted block survives the analyzer's own chain walk", function()
      -- The load-bearing assertion: not "a block was produced" but "the block
      -- verifies under the same function the analyzer will run years later".
      local out = build({ store = credentialed_store() })
      assert.equals("emitted", out.kind)

      local walked = core_enrollment.verify_identity_chain({
        identity = out.identity,
        session_pubkey = SESSION_PUBKEY,
        institution_cert = out.identity.enrollment_cert,
        session_started_at = SESSION_STARTED_AT,
      })
      assert.is_true(walked.ok)
      assert.equals("2.1", walked.value.identity_version)
    end)

    it("countersigns THIS session key and no other", function()
      local out = build({ store = credentialed_store() })
      assert.equals("emitted", out.kind)

      local lifted = core_enrollment.verify_identity_chain({
        identity = out.identity,
        session_pubkey = ("3d"):rep(32),
        institution_cert = out.identity.enrollment_cert,
        session_started_at = SESSION_STARTED_AT,
      })
      assert.is_false(lifted.ok)
      assert.equals("invalid_session_pubkey_signature", lifted.error.kind)
    end)

    it("uses the v2 binding purpose, so the signature cannot be replayed as 2.0", function()
      local out = build({ store = credentialed_store() })
      assert.equals("emitted", out.kind)
      -- Genuine under the v2 payload...
      assert.is_true(core_institution.verify_session_binding({
        institution_id = INSTITUTION_ID,
        student_ref = STUDENT_REF,
        session_pubkey = SESSION_PUBKEY,
      }, out.identity.session_pubkey_sig, global_keypair(MASTER_HEX).public_key_hex))
      -- ...and meaningless under the v1 one.
      assert.is_false(core_enrollment.verify_session_pubkey_sig({
        course_id = INSTITUTION_ID,
        student_ref = STUDENT_REF,
        session_pubkey = SESSION_PUBKEY,
      }, out.identity.session_pubkey_sig, global_keypair(MASTER_HEX).public_key_hex))
    end)
  end)

  -- -------------------------------------------------------------------------
  -- session_identity — rule 1: never block recording
  -- -------------------------------------------------------------------------

  describe("rule 1: never block recording", function()
    local function assert_skipped(out, kind)
      assert.equals("skipped", out.kind)
      assert.equals(kind, out.reason.kind)
      assert.is_nil(out.identity)
    end

    it("a cert the ROOT did not sign is refused, and recording continues", function()
      -- An unverifiable anchor must never reach the chain walk: whoever supplies
      -- the cert supplies its institution_pubkey too.
      local store = new_store()
      assert.is_true(store.import_master_secret(MASTER_HEX).ok)
      assert.is_true(
        store.save_student_credential(credential_blob({ root_priv = WRONG_ROOT_PRIV })).ok
      )
      assert_skipped(build({ store = store }), "institution_cert_not_root_signed")
    end)

    it("no embedded root key is reported, not silently skipped", function()
      assert_skipped(
        build({ store = credentialed_store(), root_pubkey_hex = "" }),
        "no_root_public_key"
      )
    end)

    it("a credential naming a key this machine does not derive is refused", function()
      -- Normally a credential obtained before the student moved machines and
      -- imported a different secret. Signing anyway would produce a
      -- countersignature that cannot verify.
      local store = new_store()
      assert.is_true(store.import_master_secret(OTHER_MASTER_HEX).ok)
      assert.is_true(store.save_student_credential(credential_blob()).ok)

      local out = build({ store = store })
      assert_skipped(out, "credential_key_mismatch")
      assert.equals(
        global_keypair(MASTER_HEX).public_key_hex,
        out.reason.credential_student_pubkey
      )
      assert.equals(
        global_keypair(OTHER_MASTER_HEX).public_key_hex,
        out.reason.derived_pubkey
      )
    end)

    it("no master secret is reported, and is never CREATED here", function()
      -- A freshly generated secret could not possibly derive the key an existing
      -- credential names, so creating one here would only manufacture a mismatch.
      local store = new_store()
      assert.is_true(store.save_student_credential(credential_blob()).ok)
      assert_skipped(build({ store = store }), "master_secret_unavailable")
      assert.is_false(store.load_master_secret().ok)
    end)

    it("MANDATORY a cross-institution forged credential is DROPPED, not emitted", function()
      -- Every signature genuine: a genuinely ROOT-certified stanford key mints a
      -- credential naming BERKELEY and it ships with stanford's own genuine
      -- cert. Only comparing institution_id across the credential, the cert and
      -- the root-verified anchor refuses it — and rule 2 then means the block is
      -- dropped rather than written into a signed, hash-chained session.start.
      --
      -- The store's importer already refuses this pair, so the only way it can
      -- reach session_identity is a HAND-EDITED store file. That is exactly the
      -- case worth pinning: the last gate must not depend on the first one.
      local dir = vim.fn.tempname()
      vim.fn.mkdir(dir, "p")
      table.insert(tempdirs, dir)
      local path = dir .. "/identity.json"

      local stanford_cert = institution_cert({
        institution_id = OTHER_INSTITUTION_ID,
        institution_pubkey = pub_hex(OTHER_INSTITUTION_PRIV),
      })
      local berkeley_claiming = student_credential({
        institution_id = INSTITUTION_ID,
        institution_priv = OTHER_INSTITUTION_PRIV,
      })

      -- The links really are individually genuine.
      assert.is_true(
        core_institution.verify_institution_cert(stanford_cert, pub_hex(ROOT_PRIV)),
        "the travelling cert IS root-certified"
      )
      assert.is_true(
        core_institution.verify_student_credential(
          berkeley_claiming,
          stanford_cert.institution_pubkey
        ),
        "the credential IS signed by the key that cert names"
      )

      vim.fn.writefile({ vim.json.encode({
        format_version = "1.0",
        master_secret = MASTER_HEX,
        enrollments = vim.empty_dict(),
        credential = { enrollment = berkeley_claiming, enrollment_cert = stanford_cert },
      }) }, path)

      local store = secret_store.new({ path = path })
      assert.is_table(store.load_student_credential(), "the hand-edited pair must load")

      local out = session_identity.build({
        manifest = manifest_2_0(),
        session_pubkey_hex = SESSION_PUBKEY,
        session_started_at = SESSION_STARTED_AT,
        root_pubkey_hex = pub_hex(ROOT_PRIV),
        store = store,
      })
      assert.equals("skipped", out.kind, "a forged identity must never be emitted")
      assert.equals("chain_did_not_verify", out.reason.kind)
      assert.equals("institution_mismatch", out.reason.error.kind)
      assert.equals(INSTITUTION_ID, out.reason.error.credential_institution_id)
      assert.equals(OTHER_INSTITUTION_ID, out.reason.error.cert_institution_id)
      assert.is_nil(out.identity)
    end)

    it("an expired credential still records — expiry is reported, never enforced", function()
      local store = new_store()
      assert.is_true(store.import_master_secret(MASTER_HEX).ok)
      assert.is_true(store.save_student_credential(credential_blob({
        issued_at = "2025-09-01T00:00:00Z",
        expires_at = "2025-12-15",
      })).ok)

      local out = build({ store = store })
      assert.equals("emitted", out.kind, "an expired credential must NOT stop recording")
      assert.is_false(out.verified.token_window.in_window)
      assert.equals("after_valid_until", out.verified.token_window.reason)
    end)

    it("an unusable session pubkey is reported, and recording continues", function()
      assert_skipped(
        build({ store = credentialed_store(), session_pubkey_hex = "nope" }),
        "invalid_session_pubkey"
      )
    end)

    it("no store at all reads as not enrolled, and never raises", function()
      local out = build({ store = nil })
      assert.equals("skipped", out.kind)
      assert.is_nil(out.identity)
    end)
  end)

  -- -------------------------------------------------------------------------
  -- Precedence: 2.1 decides, with NO fallback to 2.0
  -- -------------------------------------------------------------------------

  describe("precedence between the two families", function()
    it("a student holding BOTH records under 2.1", function()
      local store = new_store()
      assert.is_true(store.import_master_secret(MASTER_HEX).ok)
      assert.is_true(store.save_identity_artifact(enrollment_blob()).ok)
      assert.is_true(store.save_identity_artifact(credential_blob()).ok)

      local out = build({ store = store })
      assert.equals("emitted", out.kind)
      assert.equals("2.1", out.verified.identity_version)
      assert.equals(STUDENT_REF, out.verified.student_ref)
      assert.is_not.equals(COURSE_STUDENT_REF, out.verified.student_ref)
    end)

    it("MANDATORY a FAILING 2.1 path does NOT fall back to a usable 2.0 token", function()
      -- The two families attribute to DIFFERENT refs — 2.0's is per-course,
      -- 2.1's is global — so a silent fallback would file this session under a
      -- different contributor than the student believes they are recording as,
      -- and the 2.1 problem that caused it would never surface. An integrity
      -- tool must not quietly change who it says did the work.
      local store = new_store()
      assert.is_true(store.import_master_secret(MASTER_HEX).ok)
      assert.is_true(store.save_identity_artifact(enrollment_blob()).ok)
      -- A credential whose cert the root never signed: the 2.1 path fails.
      assert.is_true(
        store.save_student_credential(credential_blob({ root_priv = WRONG_ROOT_PRIV })).ok
      )

      -- The 2.0 token on its own would emit perfectly...
      local without = new_store()
      assert.is_true(without.import_master_secret(MASTER_HEX).ok)
      assert.is_true(without.save_identity_artifact(enrollment_blob()).ok)
      local baseline = build({ store = without })
      assert.equals("emitted", baseline.kind)
      assert.equals("2.0", baseline.verified.identity_version)

      -- ...but with a 2.1 credential present, the failure is reported and the
      -- session records with NO identity rather than under the other ref.
      local out = build({ store = store })
      assert.equals("skipped", out.kind)
      assert.equals("institution_cert_not_root_signed", out.reason.kind)
      assert.is_nil(out.identity)
    end)

    it("a 2.1 credential works in a 1.x workspace, where 2.0 could not", function()
      -- The 2.1 path does not consult the manifest at all. This is the point of
      -- the change: the 2.0 design could not produce an identity before the
      -- student's first submission.
      local out = build({
        store = credentialed_store(),
        manifest = { format_version = "1.0", assignment_id = "proj2", semester = "fa26" },
      })
      assert.equals("emitted", out.kind)
      assert.equals("2.1", out.verified.identity_version)
    end)

    it("ARCHIVED 2.0 still records when no 2.1 credential is stored", function()
      -- Adjudicating a case years after the fact is the entire justification for
      -- this system, and a student mid-semester must not be stranded.
      local store = new_store()
      assert.is_true(store.import_master_secret(MASTER_HEX).ok)
      assert.is_true(store.save_identity_artifact(enrollment_blob()).ok)

      local out = build({ store = store })
      assert.equals("emitted", out.kind)
      assert.equals("2.0", out.verified.identity_version)
      assert.equals("course", out.verified.scope)
      assert.equals(COURSE_ID, out.verified.course_id)
    end)
  end)
end)
