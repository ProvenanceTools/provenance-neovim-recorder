local sha256 = require("provenance.core.sha256")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local ed25519 = require("provenance.core.ed25519")
local manifest = require("provenance.core.manifest")
local bundle = require("provenance.core.bundle")
local hkdf = require("provenance.core.hkdf")
local session_keys = require("provenance.core.session_keys")
local checkpoint = require("provenance.core.checkpoint")

local function to_hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end
local function from_hex(h)
  return (h:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

-- NOTE: `<sfile>` (per the task brief) does not resolve to this file under
-- plenary's busted runner: specs are loaded via `loadfile()`, not `:source`,
-- so `vim.fn.expand("<sfile>:p")` yields "command line" rather than this
-- file's path. `debug.getinfo` reads the Lua chunk's own source instead,
-- which loadfile() sets correctly (as "@<path>").
local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture(name)
  local dir = this_file_dir() .. "/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. name), "\n"))
end

describe("conformance: format vectors (vectors.json)", function()
  local v = load_fixture("vectors.json")

  it("sha256 vectors match", function()
    for _, case in ipairs(v.sha256) do
      assert.equals(case.hex, sha256.hex(case.input))
    end
  end)

  it("chain vectors match", function()
    for _, case in ipairs(v.chain) do
      local e = case.envelope
      local env = envelope.new(e.seq, e.t, e.wall, e.kind, e.data)
      assert.equals(case.hash, hc.chain_entry(case.prev_hash, env).hash)
    end
  end)
end)

describe("conformance: ed25519 vector (ed25519.json == @noble/ed25519)", function()
  local fx = load_fixture("ed25519.json")
  local priv = ed25519.from_hex(fx.priv_hex)

  it("public key matches", function()
    assert.equals(fx.pub_hex, ed25519.to_hex(ed25519.public_key_of(priv)))
  end)

  it("deterministic signature matches", function()
    assert.equals(fx.sig_hex, ed25519.to_hex(ed25519.sign(fx.msg_utf8, priv)))
  end)

  it("signature verifies", function()
    assert.is_true(ed25519.verify(ed25519.from_hex(fx.sig_hex), fx.msg_utf8, ed25519.from_hex(fx.pub_hex)))
  end)
end)

describe("conformance: manifest vector (manifest.json — activation gate)", function()
  local fx = load_fixture("manifest.json")

  it("parses and verifies the untouched fixture", function()
    local parsed = manifest.parse(vim.json.encode(fx.manifest))
    assert.is_true(parsed.ok)
    assert.is_true(manifest.verify(parsed.value, fx.course_pubkey_hex))
  end)

  it("verifies false if any field is mutated", function()
    for _, field in ipairs({ "assignment_id", "semester", "issued_at", "sig" }) do
      local decoded = vim.json.decode(vim.json.encode(fx.manifest))
      decoded[field] = decoded[field]:sub(1, -2) .. (decoded[field]:sub(-1) == "a" and "b" or "a")
      local parsed = manifest.parse(vim.json.encode(decoded))
      if parsed.ok then
        assert.is_false(manifest.verify(parsed.value, fx.course_pubkey_hex), field .. " mutation should break verification")
      end
    end

    local decoded = vim.json.decode(vim.json.encode(fx.manifest))
    decoded.files_under_review = { "src/tampered.py" }
    local parsed = manifest.parse(vim.json.encode(decoded))
    assert.is_true(parsed.ok)
    assert.is_false(manifest.verify(parsed.value, fx.course_pubkey_hex))
  end)
end)

describe("conformance: bundle-manifest.json (byte-exact JCS pin + verify_sig)", function()
  local fx = load_fixture("bundle-manifest.json")

  it("bundle.build + to_canonical reproduces the fixture's canonical_json exactly", function()
    local built = bundle.build(fx.manifest)
    assert.equals(fx.canonical_json, bundle.to_canonical(built))
  end)

  it("verify_sig is true for the fixture's canonical_json/signature/pubkey", function()
    assert.is_true(bundle.verify_sig(fx.canonical_json, fx.signature_hex, fx.session_pubkey_hex))
  end)

  it("sign -> verify_sig round-trips with a locally generated keypair", function()
    local priv, pub_hex = ed25519.generate_keypair()
    local built = bundle.build(fx.manifest)
    local signed = bundle.sign(built, priv)
    assert.equals(fx.canonical_json, signed.canonical_json)
    assert.is_true(bundle.verify_sig(signed.canonical_json, signed.signature_hex, pub_hex))
  end)
end)

describe("conformance: golden-bundle.json (real sealed 1.0 manifest validates)", function()
  local fx = load_fixture("golden-bundle.json")

  it("validate_shape accepts it", function()
    local res = bundle.validate_shape(fx.manifest)
    assert.is_true(res.ok)
  end)

  it("build() on the 1.0 manifest omits submission_files from the canonical JSON", function()
    local built = bundle.build(fx.manifest)
    assert.is_nil(bundle.to_canonical(built):find("submission_files", 1, true))
  end)
end)

describe("conformance: session-key.json (HKDF + XChaCha20-Poly1305 == @noble/ciphers)", function()
  local fx = load_fixture("session-key.json")

  it("HKDF-SHA256 reproduces the pinned hkdf_key_hex (pins HMAC+HKDF)", function()
    local key = hkdf.derive(from_hex(fx.manifest_sig), from_hex(fx.salt_hex), fx.info, 32)
    assert.equals(fx.hkdf_key_hex, to_hex(key))
  end)

  it("encrypt_privkey reproduces the pinned ciphertext_hex (AEAD framing)", function()
    local enc = session_keys.encrypt_privkey(
      from_hex(fx.privkey_hex), fx.manifest_sig, from_hex(fx.salt_hex), from_hex(fx.nonce_hex))
    assert.equals(fx.ciphertext_hex, enc.ciphertext)
  end)

  it("round-trips: decrypt(encrypt(priv)) == priv; wrong sig -> nil", function()
    local priv = from_hex(fx.privkey_hex)
    local enc = session_keys.encrypt_privkey(priv, fx.manifest_sig)
    assert.equals(priv, session_keys.decrypt_privkey(enc, fx.manifest_sig))
    assert.is_nil(session_keys.decrypt_privkey(enc, string.rep("00", 64)))
  end)
end)

describe("conformance: checkpoint.json (signed seq->hash checkpoint)", function()
  local fx = load_fixture("checkpoint.json")

  it("verifies the untouched fixture checkpoint", function()
    assert.is_true(checkpoint.verify(
      { seq = fx.seq, hash = fx.hash, sig = fx.sig }, fx.session_pubkey_hex))
  end)

  it("fails verification if the hash is tampered", function()
    assert.is_false(checkpoint.verify(
      { seq = fx.seq, hash = ("cd"):rep(32), sig = fx.sig }, fx.session_pubkey_hex))
  end)

  it("fails verification if the seq is tampered", function()
    assert.is_false(checkpoint.verify(
      { seq = fx.seq + 1, hash = fx.hash, sig = fx.sig }, fx.session_pubkey_hex))
  end)
end)

-- ---------------------------------------------------------------------------
-- Manifest 2.0 trust chain (program spec §2/§3/§4,
-- docs/superpowers/specs/2026-08-18-multicourse-program-architecture.md).
--
-- Three vector files, one per module: course-cert.json, manifest-v2.json,
-- capture-policy.json. All three are generated by the monorepo's
-- tools/export-conformance-vectors.ts — never hand-edit them here.
-- ---------------------------------------------------------------------------

local course_cert = require("provenance.core.course_cert")
local capture_policy = require("provenance.core.capture_policy")

-- Bring a raw vim.json.decode result into the value model core/manifest.lua
-- speaks (arrays tagged, nulls as json.NULL). The vector files store manifests
-- both as JSON text (parsed straight through) and as decoded objects (which
-- need this first).
local function as_manifest_value(decoded)
  return manifest.normalize(decoded)
end

describe("conformance: course-cert.json (chain step 1 + the validity window)", function()
  local fx = load_fixture("course-cert.json")

  it("canonical_json is the exact byte string the ROOT key signs (cert minus root_sig)", function()
    assert.equals(fx.canonical_json, course_cert.signed_payload(fx.valid_cert))
  end)

  it("the shipped valid_cert parses", function()
    local parsed = course_cert.parse(as_manifest_value(fx.valid_cert))
    assert.is_true(parsed.ok)
    assert.equals("berkeley-cs61b", parsed.value.course_id)
    assert.equals(fx.course_pubkey_hex, parsed.value.course_pubkey)
  end)

  for _, case in ipairs(fx.verify_cases) do
    it("verify_case '" .. case.name .. "': " .. case.note, function()
      local actual = course_cert.verify(as_manifest_value(case.input.cert), case.input.root_pubkey_hex)
      assert.equals(case.expected.valid, actual)
    end)
  end

  it("MANDATORY bad_root_sig: a cert signed by a different root does NOT verify", function()
    -- Named explicitly as well as covered by the loop above: chain step 1
    -- failing is "do not activate", and a port that stubbed verify to `true`
    -- would still pass every positive case.
    local case
    for _, c in ipairs(fx.verify_cases) do
      if c.name == "bad_root_sig" then case = c end
    end
    assert.is_not_nil(case)
    assert.is_false(course_cert.verify(as_manifest_value(case.input.cert), case.input.root_pubkey_hex))
    assert.is_false(course_cert.verify(as_manifest_value(fx.valid_cert), fx.wrong_root_pubkey_hex))
  end)

  it("the root public key is a PARAMETER, never a constant", function()
    -- Same certificate, two different roots: it must verify under exactly the
    -- one that signed it. A hardcoded root key would make one build serve one
    -- deployment, which is what this design removes.
    assert.is_true(course_cert.verify(as_manifest_value(fx.valid_cert), fx.root_pubkey_hex))
    assert.is_false(course_cert.verify(as_manifest_value(fx.valid_cert), fx.wrong_root_pubkey_hex))
  end)

  for _, case in ipairs(fx.timestamp_parse_cases) do
    it("timestamp_parse_case " .. vim.inspect(case.input), function()
      local actual = course_cert.parse_iso_instant_ms(case.input)
      if case.expected_ms == vim.NIL then
        assert.is_nil(actual, "expected a rejection for " .. vim.inspect(case.input))
      else
        assert.equals(case.expected_ms, actual)
      end
    end)
  end

  it("a date-only bound resolves ASYMMETRICALLY: valid_from day-start, valid_until end-of-day", function()
    -- The rule the three implementations are most likely to disagree on.
    -- parse_iso_instant_ms itself is unchanged and still reads a date as its
    -- FIRST instant; only valid_until's caller-side reading extends.
    assert.equals(
      course_cert.parse_iso_instant_ms("2027-01-15"),
      course_cert.parse_iso_instant_ms("2027-01-15T00:00:00Z")
    )

    -- valid_from: inclusive from the first instant of its day.
    assert.is_true(course_cert.check_window(fx.valid_cert, "2026-08-20T00:00:00Z").in_window)

    -- valid_until: inclusive through the LAST instant of its day...
    assert.is_true(course_cert.check_window(fx.valid_cert, "2027-01-15T00:00:00Z").in_window)
    assert.is_true(course_cert.check_window(fx.valid_cert, "2027-01-15T12:00:00Z").in_window)
    assert.is_true(course_cert.check_window(fx.valid_cert, "2027-01-15T23:59:59.999Z").in_window)
    -- ...and out at the first instant of the next day.
    assert.equals(
      "after_valid_until",
      course_cert.check_window(fx.valid_cert, "2027-01-16T00:00:00Z").reason
    )
  end)

  it("the exclusive upper bound is next-midnight for a date, +1ms for a timestamp", function()
    -- The framing matters as much as the result: an exclusive next-midnight
    -- bound cannot be undercut by a 23:59:59.999 precision trap. A full
    -- timestamp keeps its exact-instant meaning and is NOT extended to
    -- end-of-day.
    local day = 24 * 60 * 60 * 1000
    assert.equals(
      course_cert.parse_iso_instant_ms("2027-01-16T00:00:00Z"),
      course_cert.resolve_valid_until_exclusive_ms("2027-01-15")
    )
    assert.equals(
      course_cert.parse_iso_instant_ms("2027-01-15") + day,
      course_cert.resolve_valid_until_exclusive_ms("2027-01-15")
    )
    assert.equals(
      course_cert.parse_iso_instant_ms("2027-01-15T09:30:00Z") + 1,
      course_cert.resolve_valid_until_exclusive_ms("2027-01-15T09:30:00Z")
    )
    assert.is_nil(course_cert.resolve_valid_until_exclusive_ms("not a date"))

    -- A full-timestamp valid_until expires the millisecond after, with no
    -- end-of-day extension.
    local cert = { valid_from = "2026-08-20", valid_until = "2027-01-15T09:30:00Z" }
    assert.is_true(course_cert.check_window(cert, "2027-01-15T09:30:00.000Z").in_window)
    assert.equals("after_valid_until", course_cert.check_window(cert, "2027-01-15T09:30:00.001Z").reason)
  end)

  it("leap seconds and 24:00:00 are rejected, non-existent calendar dates are not rolled forward", function()
    assert.is_nil(course_cert.parse_iso_instant_ms("2026-12-31T23:59:60Z"))
    assert.is_nil(course_cert.parse_iso_instant_ms("2026-09-08T24:00:00Z"))
    assert.is_nil(course_cert.parse_iso_instant_ms("2026-02-31"))
    assert.is_nil(course_cert.parse_iso_instant_ms("2027-02-29"))
    assert.is_not_nil(course_cert.parse_iso_instant_ms("2028-02-29"))
  end)

  for _, case in ipairs(fx.window_cases) do
    it("window_case '" .. case.name .. "': " .. case.note, function()
      local cert = {
        valid_from = case.input.valid_from,
        valid_until = case.input.valid_until,
      }
      local actual = course_cert.check_window(cert, case.input.issued_at)
      assert.equals(case.expected.in_window, actual.in_window)
      if case.expected.reason == nil or case.expected.reason == vim.NIL then
        assert.is_nil(actual.reason)
      else
        assert.equals(case.expected.reason, actual.reason)
      end
    end)
  end

  it("MANDATORY expired_long_ago_but_contemporaneous: the window is evaluated against issued_at, never now()", function()
    -- A cert that lapsed in 1999 wall-clock terms, with a manifest issued
    -- inside it, MUST be in_window. This is the case that catches an
    -- implementation reaching for the system clock: a Fall 2026 bundle has to
    -- still verify in 2028 for an adjudication case.
    local case
    for _, c in ipairs(fx.window_cases) do
      if c.name == "expired_long_ago_but_contemporaneous" then case = c end
    end
    assert.is_not_nil(case)
    assert.is_true(case.expected.in_window)
    local cert = { valid_from = case.input.valid_from, valid_until = case.input.valid_until }
    assert.is_true(course_cert.check_window(cert, case.input.issued_at).in_window)
  end)

  it("parse rejects a malformed cert without throwing", function()
    for _, bad in ipairs({
      { reason = "not an object", value = "nope" },
      { reason = "missing root_sig", value = { course_id = "c", course_pubkey = string.rep("a", 64), valid_from = "2026-01-01", valid_until = "2026-02-01" } },
      { reason = "short pubkey", value = { course_id = "c", course_pubkey = "aa", valid_from = "2026-01-01", valid_until = "2026-02-01", root_sig = string.rep("a", 128) } },
      { reason = "unparseable bound", value = { course_id = "c", course_pubkey = string.rep("a", 64), valid_from = "whenever", valid_until = "2026-02-01", root_sig = string.rep("a", 128) } },
      { reason = "inverted window", value = { course_id = "c", course_pubkey = string.rep("a", 64), valid_from = "2027-01-01", valid_until = "2026-02-01", root_sig = string.rep("a", 128) } },
    }) do
      local ok, res = pcall(course_cert.parse, bad.value)
      assert.is_true(ok, bad.reason .. " must not throw")
      assert.is_false(res.ok, bad.reason .. " must be rejected")
    end
  end)
end)

describe("conformance: manifest-v2.json (the trust chain, program spec §3)", function()
  local fx = load_fixture("manifest-v2.json")

  local function chain_outcome(res)
    if res.ok then
      return { ok = true, course_id = res.value.course_id, window = res.value.window }
    end
    local out = { ok = false }
    for k, v in pairs(res.error) do
      out[k] = v
    end
    return out
  end

  -- The vectors' `expected` objects come out of vim.json.decode, so absent
  -- optional fields are simply missing rather than vim.NIL. assert.same over
  -- the two tables is therefore an exact structural comparison.
  local function assert_chain(expected, res, label)
    assert.same(expected, chain_outcome(res), label)
  end

  it("MANDATORY legacy_no_format_version: a missing format_version defaults to 1.0 and PARSES", function()
    local case = fx.legacy_no_format_version
    local parsed = manifest.parse(case.manifest_json)
    assert.is_true(parsed.ok, "a 1.x manifest must never be rejected")
    assert.equals(case.expected.parses, parsed.ok)
    assert.equals(case.expected.format_version, parsed.value.format_version)
    assert.equals(case.canonical_json, manifest.signed_payload(parsed.value))
    assert.equals(case.expected.sig_verifies, manifest.verify(parsed.value, case.course_pubkey_hex))
  end)

  it("the 1.x signed payload is byte-identical to the pre-2.0 bytes (adding 2.0 moved nothing)", function()
    -- Same sig hex as manifest.json's, over the same four fields: no
    -- format_version key in the 1.x payload.
    local legacy = load_fixture("manifest.json")
    local parsed = manifest.parse(fx.legacy_no_format_version.manifest_json)
    assert.equals(legacy.manifest.sig, parsed.value.sig)
    assert.equals(legacy.course_pubkey_hex, fx.legacy_no_format_version.course_pubkey_hex)
  end)

  it("legacy_explicit_1_0: an explicit '1.0' canonicalizes to the same four legacy fields", function()
    local explicit = manifest.parse(vim.json.encode(fx.legacy_explicit_1_0.manifest))
    assert.is_true(explicit.ok)
    assert.equals("1.0", explicit.value.format_version)
    assert.equals(fx.legacy_no_format_version.canonical_json, manifest.signed_payload(explicit.value))
    assert.equals(fx.legacy_explicit_1_0.expected.sig, explicit.value.sig)
    assert.is_true(manifest.verify(explicit.value, fx.legacy_no_format_version.course_pubkey_hex))
  end)

  it("valid_2_0: canonical_json is the exact byte string the COURSE key signed (no sig, no course_cert)", function()
    local parsed = manifest.parse(vim.json.encode(fx.valid_2_0.manifest))
    assert.is_true(parsed.ok)
    assert.equals("2.0", parsed.value.format_version)
    assert.equals(fx.valid_2_0.canonical_json, manifest.signed_payload(parsed.value))
    assert.is_false(fx.valid_2_0.canonical_json:find("course_cert", 1, true) ~= nil)
    assert.is_false(fx.valid_2_0.canonical_json:find('"sig"', 1, true) ~= nil)
  end)

  it("MANDATORY unknown_keys_ignored: unknown top-level keys are ignored and do not move the signed bytes", function()
    local case = fx.unknown_keys_ignored
    local parsed = manifest.parse(case.manifest_json)
    assert.equals(case.expected.parses, parsed.ok)
    assert.equals(fx.valid_2_0.canonical_json, manifest.signed_payload(parsed.value))
    assert_chain(case.expected.chain, manifest.verify_chain(parsed.value, fx.root_pubkey_hex))
  end)

  it("2.0 requires the full field set: dropping any one of them is a parse error", function()
    -- A fixed signed key set is what lets three hand-written canonicalizers
    -- agree without a "which optionals were present" rule.
    for _, field in ipairs({ "course_id", "collaboration", "submission", "scope", "policy", "course_cert" }) do
      local decoded = vim.json.decode(vim.json.encode(fx.valid_2_0.manifest))
      decoded[field] = nil
      local parsed = manifest.parse(vim.json.encode(decoded))
      assert.is_false(parsed.ok, "a 2.0 manifest without '" .. field .. "' must not parse")
    end
  end)

  for _, case in ipairs(fx.chain_cases) do
    it("chain_case '" .. case.name .. "': " .. case.note, function()
      local m = as_manifest_value(case.input.manifest)
      assert_chain(case.expected, manifest.verify_chain(m, case.input.root_pubkey_hex), case.name)
    end)
  end

  it("MANDATORY bad_root_sig: step 1 fails and the chain is refused", function()
    local case
    for _, c in ipairs(fx.chain_cases) do
      if c.name == "bad_root_sig" then case = c end
    end
    assert.is_not_nil(case)
    local res = manifest.verify_chain(as_manifest_value(case.input.manifest), case.input.root_pubkey_hex)
    assert.is_false(res.ok)
    assert.equals("invalid_root_signature", res.error.kind)
  end)

  it("MANDATORY course_id_mismatch: both signatures are genuine and it is still a forgery", function()
    -- The cert really is root-signed for berkeley-cs61b, and the payload really
    -- is signed by the key that cert authorizes. Only step 3 catches it. Skip
    -- step 3 and 61B's key can forge a 61C manifest.
    local case
    for _, c in ipairs(fx.chain_cases) do
      if c.name == "course_id_mismatch" then case = c end
    end
    assert.is_not_nil(case)
    local m = as_manifest_value(case.input.manifest)
    local parsed = manifest.parse_value(m)
    assert.is_true(parsed.ok)
    -- steps 1 and 2 in isolation both PASS ...
    assert.is_true(course_cert.verify(parsed.value.course_cert, case.input.root_pubkey_hex))
    assert.is_true(manifest.verify(parsed.value, parsed.value.course_cert.course_pubkey))
    -- ... and the chain still refuses it.
    local res = manifest.verify_chain(m, case.input.root_pubkey_hex)
    assert.is_false(res.ok)
    assert.equals("course_id_mismatch", res.error.kind)
    assert.equals("berkeley-cs61c", res.error.manifest_course_id)
    assert.equals("berkeley-cs61b", res.error.cert_course_id)
  end)

  it("MANDATORY downgrade_1x_with_stapled_cert: step 0 refuses it, and every signature in it is genuine", function()
    -- Built with NO private key: a genuinely 61B-signed 1.x manifest, plus
    -- 61B's real (public, root-signed, copyable) certificate, plus a course_id
    -- chosen to satisfy step 3, plus an INVENTED policy turning capture off.
    -- An implementation that walks steps 1-4 without the format_version gate
    -- hands students an off switch.
    local case
    for _, c in ipairs(fx.chain_cases) do
      if c.name == "downgrade_1x_with_stapled_cert" then case = c end
    end
    assert.is_not_nil(case)
    local raw = case.input.manifest
    local m = as_manifest_value(raw)

    -- The attack's ingredients are all individually valid:
    assert.is_nil(raw.format_version)
    assert.is_true(course_cert.verify(as_manifest_value(raw.course_cert), case.input.root_pubkey_hex))
    assert.equals(raw.course_id, raw.course_cert.course_id)
    local parsed = manifest.parse(vim.json.encode(raw))
    assert.is_true(parsed.ok, "it parses fine — as 1.x")
    assert.is_true(manifest.verify(parsed.value, raw.course_cert.course_pubkey))
    assert.is_false(raw.policy.capture.selection_change)

    -- and step 0 refuses it anyway.
    local res = manifest.verify_chain(m, case.input.root_pubkey_hex)
    assert.is_false(res.ok)
    assert.equals("not_manifest_2_0", res.error.kind)
    assert.equals("1.0", res.error.format_version)

    -- The stapled policy never becomes the effective policy: a 1.x manifest
    -- carries no policy at all, so resolution falls back to capture-everything.
    assert.same(capture_policy.DEFAULTS, capture_policy.resolve(parsed.value.policy))
  end)

  it("step 0b: a 2.0 manifest missing `policy` must not chain (an omitted key would drop out of the signed bytes)", function()
    local decoded = vim.json.decode(vim.json.encode(fx.valid_2_0.manifest))
    decoded.policy = nil
    local res = manifest.verify_chain(as_manifest_value(decoded), fx.root_pubkey_hex)
    assert.is_false(res.ok)
    assert.equals("invalid_manifest_shape", res.error.kind)
    assert.equals("policy", res.error.field)
  end)

  it("a non-ASCII object key inside `policy` is rejected (bytewise vs UTF-16 key sort)", function()
    -- This repo's JCS sorts keys bytewise; JS and Kotlin sort by UTF-16 code
    -- unit. They agree only for ASCII, so a non-ASCII key would silently
    -- produce different signed bytes here than in the other two recorders.
    local decoded = vim.json.decode(vim.json.encode(fx.valid_2_0.manifest))
    decoded.policy = { ["\240\159\148\145"] = true }
    local parsed = manifest.parse(vim.json.encode(decoded))
    assert.is_false(parsed.ok)
    assert.equals("object keys must be printable ASCII", parsed.error.reason)
  end)
end)

describe("conformance: capture-policy.json (program spec §4)", function()
  local fx = load_fixture("capture-policy.json")

  it("defaults match log-core's DEFAULT_CAPTURE_POLICY", function()
    assert.same(fx.defaults, capture_policy.DEFAULTS)
  end)

  it("the heartbeat clamp range matches", function()
    assert.equals(fx.heartbeat_clamp.min_ms, capture_policy.HEARTBEAT_INTERVAL_MIN_MS)
    assert.equals(fx.heartbeat_clamp.max_ms, capture_policy.HEARTBEAT_INTERVAL_MAX_MS)
  end)

  it("the hard floor matches exactly — these kinds have no policy.capture key at all", function()
    local expected = vim.deepcopy(fx.floor_event_kinds)
    local actual = vim.deepcopy(capture_policy.FLOOR_EVENT_KINDS)
    table.sort(expected)
    table.sort(actual)
    assert.same(expected, actual)
  end)

  it("policy_gated_event_kinds matches, and is disjoint from the floor", function()
    assert.same(fx.policy_gated_event_kinds, capture_policy.POLICY_GATED_EVENT_KINDS)
    for _, kind in ipairs(capture_policy.FLOOR_EVENT_KINDS) do
      assert.is_nil(capture_policy.POLICY_GATED_EVENT_KINDS[kind], kind .. " is on the floor and must not be gated")
    end
  end)

  for _, case in ipairs(fx.cases) do
    it("policy_case '" .. case.name .. "': " .. case.note, function()
      assert.same(case.expected, capture_policy.resolve(case.input))
    end)
  end

  it("all seven heartbeat clamp boundaries resolve as the vectors say", function()
    -- Named explicitly as well as covered by the loop: the clamp is the one
    -- numeric knob a course can set, and both bounds are inclusive.
    local by_name = {}
    for _, case in ipairs(fx.cases) do
      by_name[case.name] = case
    end
    for _, name in ipairs({
      "heartbeat_below_floor",
      "heartbeat_at_floor",
      "heartbeat_in_range",
      "heartbeat_at_ceiling",
      "heartbeat_above_ceiling",
      "heartbeat_zero",
      "heartbeat_non_number",
    }) do
      local case = by_name[name]
      assert.is_not_nil(case, name .. " must be present in the vectors")
      assert.equals(
        case.expected.heartbeat_interval_ms,
        capture_policy.resolve(case.input).heartbeat_interval_ms,
        name
      )
    end
    assert.equals(5000, by_name.heartbeat_at_floor.expected.heartbeat_interval_ms)
    assert.equals(120000, by_name.heartbeat_at_ceiling.expected.heartbeat_interval_ms)
    assert.equals(30000, by_name.heartbeat_non_number.expected.heartbeat_interval_ms)
  end)

  it("floor kinds are always captured; gated kinds follow the policy", function()
    local all_off = capture_policy.resolve({
      capture = {
        selection_change = false,
        focus_change = false,
        terminal = false,
      },
    })
    for _, kind in ipairs(capture_policy.FLOOR_EVENT_KINDS) do
      assert.is_true(capture_policy.is_event_kind_captured(kind, all_off), kind .. " is on the floor")
    end
    for kind in pairs(capture_policy.POLICY_GATED_EVENT_KINDS) do
      assert.is_false(capture_policy.is_event_kind_captured(kind, all_off), kind .. " must be gated off")
      assert.is_true(capture_policy.is_event_kind_captured(kind, capture_policy.DEFAULTS))
    end
    -- An unknown kind is treated as floor: never silently dropped.
    assert.is_true(capture_policy.is_event_kind_captured("some.future.kind", all_off))
  end)
end)

-- ---------------------------------------------------------------------------
-- S2 identity layer (program spec §S2): enrollment.json + student-keys.json.
-- Generated by the monorepo's tools/export-conformance-vectors.ts — never
-- hand-edit them here.
-- ---------------------------------------------------------------------------

local enrollment = require("provenance.core.enrollment")
local student_keys = require("provenance.core.student_keys")

describe("conformance: student-keys.json (per-course key derivation)", function()
  local fx = load_fixture("student-keys.json")

  it("the pinned HKDF parameters match, byte for byte", function()
    -- A divergence in ANY of these silently breaks everything: a signature made
    -- in one editor would not verify against the pubkey the student's token
    -- names, and the failure would look like tampering.
    assert.equals("HKDF-SHA256", fx.algorithm)
    assert.equals("SHA-256", fx.hkdf_params.hash)
    assert.equals(fx.hkdf_params.salt_utf8, student_keys.HKDF_SALT)
    assert.equals(fx.hkdf_params.salt_hex, to_hex(student_keys.HKDF_SALT))
    assert.equals(25, #student_keys.HKDF_SALT)
    assert.equals(fx.hkdf_params.info_prefix_utf8, student_keys.HKDF_INFO_PREFIX)
    assert.equals(fx.hkdf_params.output_length_bytes, student_keys.SEED_BYTES)
    assert.equals(fx.master_secret_bytes, student_keys.MASTER_SECRET_BYTES)
  end)

  it("the info prefix ends in a colon", function()
    -- The separator is what makes `cs61b` and `cs61b-extra` derive different
    -- keys. Asserted on its own so a port that drops it fails here, with a
    -- readable reason, rather than only in the collision case below.
    assert.equals(":", student_keys.HKDF_INFO_PREFIX:sub(-1))
  end)

  for _, case in ipairs(fx.derivation_cases) do
    it("derivation_case " .. vim.inspect(case.input.course_id) .. ": " .. case.note, function()
      local master = from_hex(case.input.master_secret_hex)
      assert.equals(32, #master)

      assert.equals(case.expected.info_utf8, student_keys.HKDF_INFO_PREFIX .. case.input.course_id)

      local seed = student_keys.derive_course_key_seed(master, case.input.course_id)
      assert.equals(32, #seed)
      assert.equals(case.expected.seed_hex, to_hex(seed))

      local kp = student_keys.derive_course_keypair(master, case.input.course_id)
      assert.equals(case.expected.pubkey_hex, kp.public_key_hex)
      -- The seed IS the private key, verbatim: no rejection sampling, no retry.
      assert.equals(seed, kp.private_key)
    end)
  end

  it("MANDATORY cs61b / cs61b-extra do NOT collide", function()
    -- This case exists specifically to catch a port that concatenates the info
    -- prefix and course_id without the separator. Compared directly rather than
    -- only via the loop above so the failure names the actual problem.
    local by_id = {}
    for _, case in ipairs(fx.derivation_cases) do
      by_id[case.input.course_id] = case
    end
    local short, long = by_id["cs61b"], by_id["cs61b-extra"]
    assert.is_not_nil(short)
    assert.is_not_nil(long)
    assert.is_not.equals(short.expected.seed_hex, long.expected.seed_hex)

    local master = from_hex(short.input.master_secret_hex)
    assert.is_not.equals(
      to_hex(student_keys.derive_course_key_seed(master, "cs61b")),
      to_hex(student_keys.derive_course_key_seed(master, "cs61b-extra"))
    )
  end)

  it("the same student derives UNLINKABLE keys in two courses", function()
    -- The privacy claim: two courses comparing rosters cannot tell that two
    -- entries are the same person.
    local master = from_hex(fx.derivation_cases[1].input.master_secret_hex)
    local a = student_keys.derive_course_keypair(master, "berkeley-cs61b")
    local b = student_keys.derive_course_keypair(master, "berkeley-cs61c")
    assert.is_not.equals(a.public_key_hex, b.public_key_hex)
  end)

  it("a NON-ASCII course_id derives correctly", function()
    -- Safe because course_id enters as a VALUE inside a flat UTF-8 byte string,
    -- never as a JSON object key — UTF-8 encoding is unambiguous across all
    -- three languages, whereas this port's bytewise object-key ordering is not.
    local case
    for _, c in ipairs(fx.derivation_cases) do
      if c.input.course_id:find("caf") then case = c end
    end
    assert.is_not_nil(case, "the non-ASCII derivation case must be present")
    local master = from_hex(case.input.master_secret_hex)
    assert.equals(
      case.expected.pubkey_hex,
      student_keys.derive_course_keypair(master, case.input.course_id).public_key_hex
    )
  end)

  it("derivation is deterministic, and raises on malformed input", function()
    local master = from_hex(fx.derivation_cases[1].input.master_secret_hex)
    assert.equals(
      to_hex(student_keys.derive_course_key_seed(master, "x")),
      to_hex(student_keys.derive_course_key_seed(master, "x"))
    )
    assert.is_false(pcall(student_keys.derive_course_key_seed, "short", "x"))
    assert.is_false(pcall(student_keys.derive_course_key_seed, master, ""))
    assert.is_false(pcall(student_keys.derive_course_key_seed, master, nil))
  end)
end)

describe("conformance: enrollment.json (the S2 identity chain)", function()
  local fx = load_fixture("enrollment.json")

  it("format_version and the binding purpose match", function()
    assert.equals(fx.format_version, enrollment.FORMAT_VERSION)
    assert.equals(fx.session_pubkey_binding_purpose, enrollment.SESSION_PUBKEY_BINDING_PURPOSE)
  end)

  it("canonical_json: the exact bytes each key signs", function()
    -- The single most useful value for a port: a canonicalization disagreement
    -- shows up here rather than as an inscrutable signature failure.
    assert.equals(
      fx.canonical_json.enrollment_cert,
      enrollment.enrollment_cert_signed_payload(fx.valid_enrollment_cert)
    )
    assert.equals(
      fx.canonical_json.enrollment_token,
      enrollment.enrollment_token_signed_payload(fx.valid_enrollment_token)
    )
    assert.equals(
      fx.canonical_json.session_pubkey_binding,
      enrollment.session_pubkey_binding_payload(fx.session_pubkey_binding)
    )
  end)

  it("no signed payload contains its own signature field", function()
    assert.is_nil(fx.canonical_json.enrollment_cert:find("course_sig", 1, true))
    assert.is_nil(fx.canonical_json.enrollment_token:find("enrollment_sig", 1, true))
    -- student_ref is a VALUE at a fixed ASCII key, never promoted to a key.
    assert.is_not_nil(fx.canonical_json.enrollment_token:find('"student_ref":"', 1, true))
  end)

  it("the shipped cert and token parse", function()
    local cert = enrollment.parse_enrollment_cert(fx.valid_enrollment_cert)
    assert.is_true(cert.ok)
    assert.equals(fx.enrollment_pubkey_hex, cert.value.enrollment_pubkey)

    local token = enrollment.parse_enrollment_token(fx.valid_enrollment_token)
    assert.is_true(token.ok)
    assert.equals(fx.student_pubkey_hex, token.value.student_pubkey)
    assert.equals(fx.valid_enrollment_token.student_ref, token.value.student_ref)
  end)

  it("each link verifies on its own, and only under the right key", function()
    assert.is_true(enrollment.verify_enrollment_cert(fx.valid_enrollment_cert, fx.course_pubkey_hex))
    assert.is_false(enrollment.verify_enrollment_cert(fx.valid_enrollment_cert, fx.enrollment_pubkey_hex))

    assert.is_true(
      enrollment.verify_enrollment_token(fx.valid_enrollment_token, fx.enrollment_pubkey_hex)
    )
    assert.is_false(
      enrollment.verify_enrollment_token(fx.valid_enrollment_token, fx.wrong_enrollment_pubkey_hex)
    )

    assert.is_true(enrollment.verify_session_pubkey_sig(
      fx.session_pubkey_binding, fx.session_pubkey_binding.sig, fx.student_pubkey_hex
    ))
    assert.is_false(enrollment.verify_session_pubkey_sig(
      fx.session_pubkey_binding, fx.session_pubkey_binding.sig, fx.other_student_pubkey_hex
    ))
  end)

  local function chain_outcome(res)
    if res.ok then
      return {
        ok = true,
        course_id = res.value.course_id,
        student_ref = res.value.student_ref,
        student_pubkey = res.value.student_pubkey,
        enrollment_pubkey = res.value.enrollment_pubkey,
        cert_window = res.value.cert_window,
        token_window = res.value.token_window,
      }
    end
    return { ok = false, error = res.error }
  end

  for _, case in ipairs(fx.chain_cases) do
    it("chain_case '" .. case.name .. "': " .. case.note, function()
      local res = enrollment.verify_identity_chain({
        identity = case.input.identity,
        session_pubkey = case.input.session_pubkey,
        course_cert = case.input.course_cert,
        session_started_at = case.input.session_started_at,
      })
      assert.same(case.expected, chain_outcome(res), case.name)
    end)
  end

  it("MANDATORY cross_course_forgery: every signature is genuine and it is still refused", function()
    -- 61B's course key certifies an enrollment key "for 61C", and that key mints
    -- a 61C token. Steps 1 and 2 BOTH pass. Only comparing course_id at every
    -- link rejects it — which is why all THREE ids are compared, not two.
    local case
    for _, c in ipairs(fx.chain_cases) do
      if c.name == "cross_course_forgery" then case = c end
    end
    assert.is_not_nil(case)
    local ident = case.input.identity

    -- The individual links really are genuine:
    assert.is_true(enrollment.verify_enrollment_cert(
      ident.enrollment_cert, case.input.course_cert.course_pubkey
    ))
    assert.is_true(enrollment.verify_enrollment_token(
      ident.enrollment, ident.enrollment_cert.enrollment_pubkey
    ))

    -- and the chain still refuses it.
    local res = enrollment.verify_identity_chain({
      identity = ident,
      session_pubkey = case.input.session_pubkey,
      course_cert = case.input.course_cert,
      session_started_at = case.input.session_started_at,
    })
    assert.is_false(res.ok)
    assert.equals("course_id_mismatch", res.error.kind)
    assert.equals("berkeley-cs61c", res.error.token_course_id)
    assert.equals("berkeley-cs61c", res.error.cert_course_id)
    assert.equals("berkeley-cs61b", res.error.course_cert_course_id)
  end)

  it("MANDATORY both expiry paths are NON-FATAL and reported on the success value", function()
    -- An expired credential must never stop a recorder from recording (program
    -- spec §4); the analyzer decides. Both the token side and the cert side.
    for _, name in ipairs({ "expired_token_is_NOT_fatal", "expired_enrollment_cert_is_NOT_fatal" }) do
      local case
      for _, c in ipairs(fx.chain_cases) do
        if c.name == name then case = c end
      end
      assert.is_not_nil(case, name .. " must be present in the vectors")
      assert.is_true(case.expected.ok, name .. " must succeed")

      local res = enrollment.verify_identity_chain({
        identity = case.input.identity,
        session_pubkey = case.input.session_pubkey,
        course_cert = case.input.course_cert,
        session_started_at = case.input.session_started_at,
      })
      assert.is_true(res.ok, name .. " must not be an error")

      local expired_window = name == "expired_token_is_NOT_fatal"
        and res.value.token_window
        or res.value.cert_window
      assert.is_false(expired_window.in_window, name .. " must report the expiry")
      assert.equals("after_valid_until", expired_window.reason)
    end
  end)

  it("the version gate runs BEFORE any signature work", function()
    -- A wrong-version artifact is refused on the VERSION, never as a bad
    -- signature -- otherwise a future 3.0 could be walked under 2.0 rules.
    --
    -- The two error kinds changed with the 2.1 institution chain (the gate now
    -- accepts 2.0 AND 2.1), and the vectors moved with them:
    --   cert_not_2_0  -> unsupported_identity_version  (the cert declares a
    --                    version that is neither 2.0 nor 2.1)
    --   token_not_2_0 -> identity_version_mismatch     (the cert is a known
    --                    version; the credential declares a DIFFERENT one)
    -- Both are still refusals before any signature work, which is the property
    -- this test exists to pin.
    local gate = {
      cert_not_2_0 = "unsupported_identity_version",
      token_not_2_0 = "identity_version_mismatch",
    }
    for name, expected_kind in pairs(gate) do
      local case
      for _, c in ipairs(fx.chain_cases) do
        if c.name == name then case = c end
      end
      assert.is_not_nil(case, name .. " must be present in the vectors")
      assert.equals(expected_kind, case.expected.error.kind)

      -- and this port produces it, rather than merely agreeing with the fixture.
      local res = enrollment.verify_identity_chain({
        identity = case.input.identity,
        session_pubkey = case.input.session_pubkey,
        course_cert = case.input.course_cert,
        session_started_at = case.input.session_started_at,
      })
      assert.is_false(res.ok, name .. " must be refused")
      assert.equals(expected_kind, res.error.kind)
    end
  end)

  for _, case in ipairs(fx.token_window_cases) do
    it("token_window_case '" .. case.name .. "': " .. case.note, function()
      local token = { issued_at = case.input.issued_at, expires_at = case.input.expires_at }
      local actual = enrollment.check_token_window(token, case.input.at)
      assert.equals(case.expected.in_window, actual.in_window)
      if case.expected.reason == nil or case.expected.reason == vim.NIL then
        assert.is_nil(actual.reason)
      else
        assert.equals(case.expected.reason, actual.reason)
      end
    end)
  end

  it("a date-only expires_at is inclusive through end-of-day, same rule as course_cert", function()
    -- Implemented ONCE in this port: check_window delegates to course_cert's
    -- parse_iso_instant_ms + resolve_valid_until_exclusive_ms.
    local token = { issued_at = "2026-09-01T00:00:00Z", expires_at = "2027-01-15" }
    assert.is_true(enrollment.check_token_window(token, "2027-01-15T23:59:59.999Z").in_window)
    assert.equals(
      "after_valid_until",
      enrollment.check_token_window(token, "2027-01-16T00:00:00Z").reason
    )
  end)

  it("parse rejects malformed artifacts without throwing", function()
    for _, bad in ipairs({
      { why = "not an object", value = "nope" },
      { why = "missing course_sig", value = {
        format_version = "2.0", course_id = "c", enrollment_pubkey = ("a"):rep(64),
        valid_from = "2026-01-01", valid_until = "2026-06-01" } },
      { why = "inverted window", value = {
        format_version = "2.0", course_id = "c", enrollment_pubkey = ("a"):rep(64),
        valid_from = "2027-01-01", valid_until = "2026-06-01", course_sig = ("a"):rep(128) } },
      { why = "unparseable bound", value = {
        format_version = "2.0", course_id = "c", enrollment_pubkey = ("a"):rep(64),
        valid_from = "whenever", valid_until = "2026-06-01", course_sig = ("a"):rep(128) } },
    }) do
      local ok, res = pcall(enrollment.parse_enrollment_cert, bad.value)
      assert.is_true(ok, bad.why .. " must not throw")
      assert.is_false(res.ok, bad.why .. " must be rejected")
    end

    local ok, res = pcall(enrollment.parse_enrollment_token, { format_version = "2.0" })
    assert.is_true(ok)
    assert.is_false(res.ok)
  end)
end)

-- ---------------------------------------------------------------------------
-- S2 identity, CURRENT: identity.json — the institution-scoped 2.1 chain.
--
-- Generated by the monorepo's tools/export-conformance-vectors.ts and
-- byte-identical to what provcode and provjet consume — never hand-edit it here.
-- If this port disagrees with the vector, the port is wrong.
--
-- Every case is walked THROUGH this port's own implementation rather than read
-- back out of the fixture: the point is to pin OUR construction and OUR routing,
-- not vim.json.decode's round-trip. Case counts are asserted up front so a
-- truncated fixture cannot silently make a loop vacuous — that failure mode has
-- bitten this programme repeatedly.
-- ---------------------------------------------------------------------------

local institution = require("provenance.core.institution")

describe("conformance: identity.json (the 2.1 institution identity chain)", function()
  local fx = load_fixture("identity.json")

  it("the fixture is complete — no loop below can be vacuous", function()
    assert.equals(12, #fx.chain_cases)
    assert.equals(2, #fx.legacy_2_0_cases)
    assert.equals(2, #fx.root_verification_cases)
    assert.equals(5, #fx.credential_window_cases)
    assert.equals(2, #fx.student_key_derivation.derivation_cases)
  end)

  it("format_version and the binding purpose match", function()
    assert.equals(fx.format_version, institution.FORMAT_VERSION)
    assert.equals(fx.session_pubkey_binding_purpose, institution.SESSION_BINDING_PURPOSE)
    -- Deliberately a DIFFERENT tag from 2.0's, so a countersignature can never
    -- be replayed across versions.
    assert.is_not.equals(
      enrollment.SESSION_PUBKEY_BINDING_PURPOSE,
      institution.SESSION_BINDING_PURPOSE
    )
  end)

  it("THE ROUTING RULE: the discriminator is the SIGNED format_version in the cert slot", function()
    -- Never which fields are present. Presence is attacker-controlled and
    -- ambiguous; this project already shipped that bug once (bundle-manifest.ts
    -- read the presence of an embedded manifest as a 2.0 claim and made the
    -- whole legacy path unreachable).
    assert.equals("enrollment_cert.format_version", fx.discriminator.field)
    assert.equals(enrollment.FORMAT_VERSION, fx.discriminator.course_scoped)
    assert.equals(institution.FORMAT_VERSION, fx.discriminator.institution_scoped)
  end)

  it("canonical_json: the exact bytes each key signs", function()
    -- The single most useful value for a port: a canonicalization disagreement
    -- shows up here as a readable string diff rather than as an inscrutable
    -- signature failure.
    assert.equals(
      fx.canonical_json.institution_cert,
      institution.institution_cert_signed_payload(fx.valid_institution_cert)
    )
    assert.equals(
      fx.canonical_json.student_credential,
      institution.student_credential_signed_payload(fx.valid_student_credential)
    )
    assert.equals(
      fx.canonical_json.session_pubkey_binding,
      institution.session_binding_payload(fx.session_pubkey_binding)
    )
  end)

  it("no signed payload contains its own signature field", function()
    assert.is_nil(fx.canonical_json.institution_cert:find("root_sig", 1, true))
    assert.is_nil(fx.canonical_json.student_credential:find("institution_sig", 1, true))
    -- student_ref is a VALUE at a fixed ASCII key, never promoted to a key.
    -- This port's JCS sorts object keys bytewise while JS and Kotlin sort by
    -- UTF-16 code unit; the two agree only for ASCII.
    assert.is_not_nil(fx.canonical_json.student_credential:find('"student_ref":"', 1, true))
    assert.is_not_nil(fx.canonical_json.session_pubkey_binding:find('"student_ref":"', 1, true))
  end)

  it("the shipped cert and credential parse", function()
    local cert = institution.parse_institution_cert(fx.valid_institution_cert)
    assert.is_true(cert.ok)
    assert.equals(fx.institution_pubkey_hex, cert.value.institution_pubkey)

    local credential = institution.parse_student_credential(fx.valid_student_credential)
    assert.is_true(credential.ok)
    assert.equals(fx.student_pubkey_hex, credential.value.student_pubkey)
    assert.equals(fx.valid_student_credential.student_ref, credential.value.student_ref)
  end)

  for _, case in ipairs(fx.root_verification_cases) do
    it("root_verification_case '" .. case.name .. "': " .. case.note, function()
      -- The institution cert is a trust anchor ONLY once its root_sig verifies
      -- against the embedded root key. verify_identity_chain does NOT do this —
      -- the caller must, exactly as for course_cert.
      assert.equals(
        case.expected.ok,
        institution.verify_institution_cert(case.input.cert, case.input.root_pubkey_hex)
      )
    end)
  end

  it("each link verifies on its own, and only under the right key", function()
    assert.is_true(
      institution.verify_student_credential(fx.valid_student_credential, fx.institution_pubkey_hex)
    )
    assert.is_false(
      institution.verify_student_credential(
        fx.valid_student_credential,
        fx.other_institution_pubkey_hex
      )
    )

    assert.is_true(institution.verify_session_binding(
      fx.session_pubkey_binding, fx.session_pubkey_binding.sig, fx.student_pubkey_hex
    ))
    assert.is_false(institution.verify_session_binding(
      fx.session_pubkey_binding, fx.session_pubkey_binding.sig, fx.other_student_pubkey_hex
    ))
  end)

  --- Project a walk result onto exactly the fields the vector pins, per version.
  local function chain_outcome(res)
    if not res.ok then
      return { ok = false, error = res.error }
    end
    if res.value.identity_version == institution.FORMAT_VERSION then
      return {
        ok = true,
        identity_version = res.value.identity_version,
        scope = res.value.scope,
        institution_id = res.value.institution_id,
        student_ref = res.value.student_ref,
        student_pubkey = res.value.student_pubkey,
        institution_pubkey = res.value.institution_pubkey,
        cert_window = res.value.cert_window,
        token_window = res.value.token_window,
      }
    end
    return {
      ok = true,
      identity_version = res.value.identity_version,
      scope = res.value.scope,
      course_id = res.value.course_id,
      student_ref = res.value.student_ref,
      student_pubkey = res.value.student_pubkey,
      enrollment_pubkey = res.value.enrollment_pubkey,
      cert_window = res.value.cert_window,
      token_window = res.value.token_window,
    }
  end

  for _, case in ipairs(fx.chain_cases) do
    it("chain_case '" .. case.name .. "': " .. case.note, function()
      local res = enrollment.verify_identity_chain({
        identity = case.input.identity,
        session_pubkey = case.input.session_pubkey,
        institution_cert = case.input.institution_cert,
        session_started_at = case.input.session_started_at,
      })
      assert.same(case.expected, chain_outcome(res), case.name)
    end)
  end

  it("MANDATORY cross_institution_forgery: every signature is genuine and it is still refused", function()
    -- Stanford holds a genuinely ROOT-certified institution key. It mints a
    -- credential naming BERKELEY and ships it with its own genuine cert. The
    -- cert verifies against root; the credential verifies against exactly the
    -- key that cert names; every signature in the bundle is real. Only comparing
    -- institution_id across the credential, the travelling cert and the
    -- root-verified anchor refuses it.
    local case
    for _, c in ipairs(fx.chain_cases) do
      if c.name == "cross_institution_forgery" then case = c end
    end
    assert.is_not_nil(case, "cross_institution_forgery is a MANDATORY vector")
    local ident = case.input.identity
    local anchor = case.input.institution_cert

    -- The individual links really are genuine:
    assert.is_true(
      institution.verify_institution_cert(anchor, fx.root_pubkey_hex),
      "the travelling cert IS root-certified"
    )
    assert.is_true(
      institution.verify_student_credential(ident.enrollment, anchor.institution_pubkey),
      "the credential IS signed by the key that cert names"
    )

    -- and the chain still refuses it.
    local res = enrollment.verify_identity_chain({
      identity = ident,
      session_pubkey = case.input.session_pubkey,
      institution_cert = anchor,
      session_started_at = case.input.session_started_at,
    })
    assert.is_false(res.ok)
    assert.equals("institution_mismatch", res.error.kind)
    assert.equals("berkeley", res.error.credential_institution_id)
    assert.equals("stanford", res.error.cert_institution_id)
    assert.equals("stanford", res.error.anchor_institution_id)
    -- The travelling cert and the anchor ARE the same cert here: the forgery is
    -- purely in the id, which is exactly why the id comparison is what catches it.
    assert.is_false(res.error.pubkey_mismatch)
  end)

  it("MANDATORY the credential is verified against the ANCHOR's key, never the travelling cert's", function()
    -- travelling_cert_names_another_key: same institution id, a different
    -- certified key. A verifier reading institution_pubkey out of the travelling
    -- cert would accept a key of the attacker's choosing.
    local case
    for _, c in ipairs(fx.chain_cases) do
      if c.name == "travelling_cert_names_another_key" then case = c end
    end
    assert.is_not_nil(case)
    local res = enrollment.verify_identity_chain({
      identity = case.input.identity,
      session_pubkey = case.input.session_pubkey,
      institution_cert = case.input.institution_cert,
      session_started_at = case.input.session_started_at,
    })
    assert.is_false(res.ok)
    assert.equals("institution_mismatch", res.error.kind)
    assert.is_true(res.error.pubkey_mismatch)
  end)

  it("MANDATORY both expiry paths are NON-FATAL and reported on the success value", function()
    -- An expired credential must never stop a recorder from recording (program
    -- spec §4); the analyzer decides. Both the credential side and the cert side.
    for _, name in ipairs({ "expired_credential_is_NOT_fatal", "expired_institution_cert_is_NOT_fatal" }) do
      local case
      for _, c in ipairs(fx.chain_cases) do
        if c.name == name then case = c end
      end
      assert.is_not_nil(case, name .. " must be present in the vectors")
      assert.is_true(case.expected.ok, name .. " must succeed")

      local res = enrollment.verify_identity_chain({
        identity = case.input.identity,
        session_pubkey = case.input.session_pubkey,
        institution_cert = case.input.institution_cert,
        session_started_at = case.input.session_started_at,
      })
      assert.is_true(res.ok, name .. " must not be an error")

      local expired_window = name == "expired_credential_is_NOT_fatal"
        and res.value.token_window
        or res.value.cert_window
      assert.is_false(expired_window.in_window, name .. " must report the expiry")
      assert.equals("after_valid_until", expired_window.reason)
    end
  end)

  it("the version gate runs BEFORE any signature work, and refuses a mixed pair", function()
    local by_name = {}
    for _, c in ipairs(fx.chain_cases) do by_name[c.name] = c end

    -- Neither 2.0 nor 2.1: refused on the version, before anything is parsed.
    for _, name in ipairs({ "cert_not_a_known_version", "future_3_0_is_not_replayable_as_2_1" }) do
      local case = by_name[name]
      assert.is_not_nil(case, name .. " must be present")
      assert.equals("unsupported_identity_version", case.expected.error.kind)
      local res = enrollment.verify_identity_chain({
        identity = case.input.identity,
        session_pubkey = case.input.session_pubkey,
        institution_cert = case.input.institution_cert,
        session_started_at = case.input.session_started_at,
      })
      assert.is_false(res.ok)
      assert.equals("unsupported_identity_version", res.error.kind)
      assert.equals("3.0", res.error.format_version)
    end

    -- A 2.1 cert paired with a 2.0-versioned credential. Refused rather than
    -- resolved: otherwise each artifact is read under rules the other never
    -- agreed to.
    local mixed = by_name["mixed_versions_are_refused"]
    assert.is_not_nil(mixed)
    local res = enrollment.verify_identity_chain({
      identity = mixed.input.identity,
      session_pubkey = mixed.input.session_pubkey,
      institution_cert = mixed.input.institution_cert,
      session_started_at = mixed.input.session_started_at,
    })
    assert.is_false(res.ok)
    assert.equals("identity_version_mismatch", res.error.kind)
    assert.equals("2.1", res.error.cert_version)
    assert.equals("2.0", res.error.credential_version)
  end)

  it("MANDATORY routes on the SIGNED version even when field PRESENCE disagrees", function()
    -- The decisive discriminator test, and the only one where the two candidate
    -- routing rules give different answers: every honest 2.1 artifact carries
    -- institution_pubkey and every honest 2.0 one does not, so on well-formed
    -- material "which fields exist" and "what the signed version says" agree,
    -- and a port that routes on presence looks perfectly correct.
    --
    -- Here they are made to DISAGREE. Presence is attacker-controlled; a signed
    -- version is not. This project already shipped the presence bug once —
    -- bundle-manifest.ts read the mere presence of an embedded manifest as a 2.0
    -- claim and made the whole legacy path unreachable.

    -- (a) INSTITUTION-shaped fields, but the cert slot SIGNS "2.0".
    -- Correct routing sends this to the COURSE walk, which refuses it on shape
    -- (no course_id, no enrollment_pubkey, no course_sig). A presence-router
    -- sends it to the INSTITUTION walk, which gets past shape and refuses it a
    -- step later, on the signature — a different, weaker answer.
    local as_2_0 = vim.json.decode(vim.json.encode(fx.chain_cases[1].input.identity))
    as_2_0.enrollment_cert.format_version = enrollment.FORMAT_VERSION
    as_2_0.enrollment.format_version = enrollment.FORMAT_VERSION
    assert.is_not_nil(as_2_0.enrollment_cert.institution_pubkey)

    local res = enrollment.verify_identity_chain({
      identity = as_2_0,
      session_pubkey = fx.chain_cases[1].input.session_pubkey,
      course_cert = { course_id = "berkeley", course_pubkey = fx.institution_pubkey_hex },
      institution_cert = fx.valid_institution_cert,
      session_started_at = fx.chain_cases[1].input.session_started_at,
    })
    assert.is_false(res.ok)
    assert.equals(
      "invalid_cert_shape",
      res.error.kind,
      "a cert SIGNING 2.0 must be walked as 2.0 however institution-shaped it looks"
    )

    -- (b) The mirror image: COURSE-shaped fields, but the cert slot SIGNS "2.1".
    local legacy = fx.legacy_2_0_cases[1].input
    local as_2_1 = vim.json.decode(vim.json.encode(legacy.identity))
    as_2_1.enrollment_cert.format_version = institution.FORMAT_VERSION
    as_2_1.enrollment.format_version = institution.FORMAT_VERSION
    assert.is_nil(as_2_1.enrollment_cert.institution_pubkey)

    local res2 = enrollment.verify_identity_chain({
      identity = as_2_1,
      session_pubkey = legacy.session_pubkey,
      course_cert = legacy.course_cert,
      institution_cert = fx.valid_institution_cert,
      session_started_at = legacy.session_started_at,
    })
    assert.is_false(res2.ok)
    assert.equals(
      "invalid_cert_shape",
      res2.error.kind,
      "a cert SIGNING 2.1 must be walked as 2.1 however course-shaped it looks"
    )
  end)

  it("a 2.1 chain with no institution anchor is refused, not walked", function()
    -- Which anchor is needed is only known after reading the bundle, so this is
    -- reported as a value rather than raised.
    local res = enrollment.verify_identity_chain({
      identity = fx.chain_cases[1].input.identity,
      session_pubkey = fx.chain_cases[1].input.session_pubkey,
      session_started_at = fx.chain_cases[1].input.session_started_at,
    })
    assert.is_false(res.ok)
    assert.equals("missing_trust_anchor", res.error.kind)
    assert.equals("institution_cert", res.error.required)
  end)

  -- -------------------------------------------------------------------------
  -- ARCHIVED 2.0 IDENTITY MUST KEEP VERIFYING, PERMANENTLY.
  --
  -- Every bundle recorded before this change carries a 2.0 identity block, and
  -- adjudicating a case years after the fact is the entire justification for
  -- this system. These cases run the SAME entry point a 2.1 bundle uses. A port
  -- whose router looks at field presence rather than the signed format_version
  -- fails here.
  -- -------------------------------------------------------------------------

  for _, case in ipairs(fx.legacy_2_0_cases) do
    it("legacy_2_0_case '" .. case.name .. "': " .. case.note, function()
      local res = enrollment.verify_identity_chain({
        identity = case.input.identity,
        session_pubkey = case.input.session_pubkey,
        course_cert = case.input.course_cert,
        session_started_at = case.input.session_started_at,
      })
      assert.same(case.expected, chain_outcome(res), case.name)
    end)
  end

  it("MANDATORY an archived 2.0 identity routes to the COURSE walk, through the 2.1 entry point", function()
    local case
    for _, c in ipairs(fx.legacy_2_0_cases) do
      if c.name == "archived_course_identity_still_verifies" then case = c end
    end
    assert.is_not_nil(case)

    -- The fixture's own artifacts declare 2.0 in the SIGNED cert slot. That, and
    -- nothing about which fields exist, is what selects the walk.
    assert.equals(enrollment.FORMAT_VERSION, case.input.identity.enrollment_cert.format_version)

    local res = enrollment.verify_identity_chain({
      identity = case.input.identity,
      session_pubkey = case.input.session_pubkey,
      course_cert = case.input.course_cert,
      session_started_at = case.input.session_started_at,
    })
    assert.is_true(res.ok, "an archived 2.0 identity must still verify")
    assert.equals("2.0", res.value.identity_version)
    assert.equals("course", res.value.scope)
    assert.equals("berkeley-cs61b", res.value.course_id)
    -- It carries NO institution fields: the two families are not interchangeable.
    assert.is_nil(res.value.institution_id)

    -- Handing the SAME archived block a 2.1 anchor and no course_cert must not
    -- accidentally walk it as 2.1 — the signed version decides, not the caller.
    local misrouted = enrollment.verify_identity_chain({
      identity = case.input.identity,
      session_pubkey = case.input.session_pubkey,
      institution_cert = fx.valid_institution_cert,
      session_started_at = case.input.session_started_at,
    })
    assert.is_false(misrouted.ok)
    assert.equals("missing_trust_anchor", misrouted.error.kind)
    assert.equals("course_cert", misrouted.error.required)
  end)

  it("MANDATORY the archived 2.0 cross-course forgery is still refused", function()
    local case
    for _, c in ipairs(fx.legacy_2_0_cases) do
      if c.name == "archived_cross_course_forgery_still_refused" then case = c end
    end
    assert.is_not_nil(case)
    local res = enrollment.verify_identity_chain({
      identity = case.input.identity,
      session_pubkey = case.input.session_pubkey,
      course_cert = case.input.course_cert,
      session_started_at = case.input.session_started_at,
    })
    assert.is_false(res.ok)
    assert.equals("course_id_mismatch", res.error.kind)
  end)

  -- -------------------------------------------------------------------------
  -- Windows and the global key derivation
  -- -------------------------------------------------------------------------

  for _, case in ipairs(fx.credential_window_cases) do
    it("credential_window_case '" .. case.name .. "': " .. case.note, function()
      local credential = {
        issued_at = case.input.issued_at,
        expires_at = case.input.expires_at,
      }
      local actual = institution.check_credential_window(credential, case.input.at)
      assert.equals(case.expected.in_window, actual.in_window)
      if case.expected.reason == nil or case.expected.reason == vim.NIL then
        assert.is_nil(actual.reason)
      else
        assert.equals(case.expected.reason, actual.reason)
      end
    end)
  end

  describe("student_key_derivation (the CURRENT global key)", function()
    local skd = fx.student_key_derivation

    it("the pinned HKDF parameters match, byte for byte", function()
      assert.equals("SHA-256", skd.hkdf_params.hash)
      -- Same salt and output rule as the legacy per-course derivation...
      assert.equals(skd.hkdf_params.salt_utf8, student_keys.HKDF_SALT)
      assert.equals(skd.hkdf_params.salt_hex, to_hex(student_keys.HKDF_SALT))
      assert.equals(skd.hkdf_params.output_length_bytes, student_keys.SEED_BYTES)
      assert.equals(skd.master_secret_bytes, student_keys.MASTER_SECRET_BYTES)
      -- ...and the ONLY difference is the info, which is now FIXED.
      assert.equals(skd.hkdf_params.info_utf8, student_keys.HKDF_INFO)
    end)

    it("the info is fully global: no course_id, no colon, pure ASCII", function()
      -- Nothing user-derived enters the info, so the UTF-8 encoding hazard that
      -- bit provjet under v1 (US_ASCII turning `berkeley-café` into a different
      -- key with no error) is retired here rather than merely mitigated.
      assert.is_not.equals(":", student_keys.HKDF_INFO:sub(-1))
      assert.is_nil(student_keys.HKDF_INFO:find("[\128-\255]"))
      assert.is_not.equals(student_keys.HKDF_INFO_PREFIX, student_keys.HKDF_INFO)
    end)

    for _, case in ipairs(skd.derivation_cases) do
      it("derivation_case: " .. case.note, function()
        local master = from_hex(case.input.master_secret_hex)
        assert.equals(32, #master)

        local seed = student_keys.derive_student_key_seed(master)
        assert.equals(32, #seed)
        assert.equals(case.expected.seed_hex, to_hex(seed))

        local kp = student_keys.derive_student_keypair(master)
        assert.equals(case.expected.pubkey_hex, kp.public_key_hex)
        -- The seed IS the private key, verbatim: no rejection sampling, no retry.
        assert.equals(seed, kp.private_key)
      end)
    end

    it("MANDATORY the global key differs from the legacy per-course key", function()
      -- Same master secret, both derivations. These MUST NOT be equal — that is
      -- what keeps a student's archived per-course keys separate from their new
      -- global one, so archived bundles keep verifying.
      local d = skd.differs_from_legacy_course_derivation
      local master = from_hex(d.master_secret_hex)
      assert.equals(
        d.global_pubkey_hex,
        student_keys.derive_student_keypair(master).public_key_hex
      )
      assert.equals(
        d.legacy_pubkey_hex,
        student_keys.derive_course_keypair(master, d.legacy_course_id).public_key_hex
      )
      assert.is_not.equals(d.global_pubkey_hex, d.legacy_pubkey_hex)
    end)

    it("derivation is deterministic, and raises on malformed input", function()
      local master = from_hex(skd.derivation_cases[1].input.master_secret_hex)
      assert.equals(
        to_hex(student_keys.derive_student_key_seed(master)),
        to_hex(student_keys.derive_student_key_seed(master))
      )
      assert.is_false(pcall(student_keys.derive_student_key_seed, "short"))
      assert.is_false(pcall(student_keys.derive_student_key_seed, nil))
    end)

    it("two students derive different global keys", function()
      local a = from_hex(skd.derivation_cases[1].input.master_secret_hex)
      local b = from_hex(skd.derivation_cases[2].input.master_secret_hex)
      assert.is_not.equals(to_hex(a), to_hex(b))
      assert.is_not.equals(
        student_keys.derive_student_keypair(a).public_key_hex,
        student_keys.derive_student_keypair(b).public_key_hex
      )
    end)
  end)
end)

-- ---------------------------------------------------------------------------
-- S5 commit-graph capture (program spec S5): git-event.json.
--
-- Generated by the monorepo's tools/export-conformance-vectors.ts and
-- byte-identical to what provcode and provjet consume — never hand-edit it
-- here. If this port disagrees with the vector, the port is wrong.
--
-- Every case is rebuilt THROUGH this port's own builder rather than read out of
-- the vector's decoded `data`: the whole point is to pin our construction —
-- which keys are omitted, that `parents` is a tagged JSON array, that its order
-- is left alone — not vim.json.decode's round-trip.
-- ---------------------------------------------------------------------------

local core_json = require("provenance.core.json")
local git_payloads = require("provenance.recorder.events.git_payloads")
local git_event = require("provenance.core.git_event")

describe("conformance: git-event.json (program spec S5 — the commit graph)", function()
  local fx = load_fixture("git-event.json")

  -- The six structural keys, and NOTHING else, may ever appear in a
  -- git.event payload. Author identity is not on this list and never will be.
  local ALLOWED_KEYS = {
    operation = true,
    commit_sha = true,
    sha = true,
    parents = true,
    branch = true,
    root_commit_sha = true,
  }

  -- Cases whose `data` a CONFORMING WRITER MUST NEVER PRODUCE (decision D12).
  -- Four spell an unusable discriminator (a repository path, an uppercased sha,
  -- an abbreviation, the empty string) and one spells the unknown case as
  -- `null` instead of omitting the key. They are in the vector so a port
  -- asserts REJECT as well as accept: a reader must still parse them, and this
  -- writer must refuse to build them. Each is driven through the builder below
  -- and required to degrade to the ABSENT bytes — not merely to "something
  -- different", which an arbitrary bug would also satisfy.
  local WRITER_MUST_REFUSE = {
    root_commit_sha_null_is_not_absent = true,
    root_commit_sha_repository_path_rejected = true,
    root_commit_sha_uppercase_rejected = true,
    root_commit_sha_abbreviated_rejected = true,
    root_commit_sha_empty_rejected = true,
  }

  --- Rebuild one vector case's payload through git_payloads.
  --- `data.parents` absent (nil) and `data.parents == []` (an empty Lua table
  --- from vim.json.decode) are the two DIFFERENT inputs the vector exists to
  --- distinguish, so presence is tested with `~= nil`, never with `#`.
  --- `data.root_commit_sha` is handed in verbatim — including `vim.NIL` for the
  --- JSON `null` case — because refusing it is the builder's job, not the
  --- test's.
  local function build(case)
    local d = case.data
    local view = nil
    if d.sha ~= nil or d.parents ~= nil then
      local parents = nil
      if d.parents ~= nil then
        parents = {}
        for i = 1, #d.parents do
          parents[i] = d.parents[i]
        end
      end
      view = git_payloads.commit_view(d.sha, parents)
    end
    return git_payloads.build_git_event(
      d.operation,
      d.commit_sha,
      view,
      d.branch,
      d.root_commit_sha
    )
  end

  local function case_named(name)
    for _, c in ipairs(fx.cases) do
      if c.name == name then
        return c
      end
    end
    return nil
  end

  local function key_set(t)
    local keys = {}
    for k in pairs(t) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    return keys
  end

  it("the vector ships all twenty cases this port must satisfy", function()
    -- Guards against a silently truncated fixture making the loops below pass
    -- by testing nothing. Eleven pre-D12 cases plus nine discriminator cases,
    -- of which five the writer must REFUSE.
    assert.equals(20, #fx.cases)
    local refuse_seen = 0
    for _, c in ipairs(fx.cases) do
      if WRITER_MUST_REFUSE[c.name] then
        refuse_seen = refuse_seen + 1
      end
    end
    assert.equals(5, refuse_seen)
  end)

  for _, case in ipairs(fx.cases) do
    if not WRITER_MUST_REFUSE[case.name] then
      it("case '" .. case.name .. "': " .. case.note, function()
        local ev = build(case)
        assert.equals("git.event", ev.kind)

        -- Byte-exact JCS of the payload.
        assert.equals(case.canonical_json, core_json.canonicalize(ev.data))

        -- ...and the chain hash of the whole envelope built around OUR payload.
        local e = case.envelope
        assert.equals("git.event", e.kind)
        local env = envelope.new(e.seq, e.t, e.wall, e.kind, ev.data)
        assert.equals(case.hash, hc.chain_entry(case.prev_hash, env).hash)

        for _, k in ipairs(key_set(ev.data)) do
          assert.is_true(ALLOWED_KEYS[k] == true, "unexpected key in git.event payload: " .. k)
        end
      end)
    end
  end

  -- -------------------------------------------------------------------------
  -- D12 — the repository discriminator. Reader rules AND writer refusals.
  -- -------------------------------------------------------------------------

  it("every case's discriminator narrows exactly as the vector publishes it", function()
    -- The reader half, run over all twenty cases. The eleven pre-D12 cases
    -- carry no `discriminator` object at all, which means `absent` — and
    -- asserting that explicitly is what pins the compatibility claim that every
    -- bundle in existence keeps reading exactly as it did before D12.
    local seen = 0
    for _, case in ipairs(fx.cases) do
      local expected = case.discriminator or { kind = "absent" }
      local got = git_event.read_repository_discriminator(case.data)
      assert.equals(expected.kind, got.kind, case.name)
      if expected.kind == "recorded" then
        assert.equals(expected.rootCommitSha, got.root_commit_sha, case.name)
      elseif expected.kind == "malformed" then
        assert.equals(expected.problem, got.problem, case.name)
      end
      seen = seen + 1
    end
    assert.equals(#fx.cases, seen)
  end)

  it("WRITER RULE: an unusable discriminator is OMITTED, degrading to the absent bytes", function()
    -- The five cases a conforming writer must never produce, each driven
    -- through this port's own builder. The assertion is not merely "different
    -- from the vector" — it is "byte-identical to the ABSENT case", which is
    -- the only correct degradation. An arbitrary bug would satisfy the former.
    local absent = case_named("root_commit_sha_absent_shallow_clone")
    assert.is_not_nil(absent)

    local checked = 0
    for _, case in ipairs(fx.cases) do
      if WRITER_MUST_REFUSE[case.name] then
        local built = build(case).data
        assert.is_nil(built.root_commit_sha, case.name .. " must omit the key")
        assert.are_not.equals(
          case.canonical_json,
          core_json.canonicalize(built),
          case.name .. " must not reproduce the nonconforming bytes"
        )
        checked = checked + 1
      end
    end
    assert.equals(5, checked)

    -- The `null` case in particular: same payload as the absent case except for
    -- the explicit null, so refusing it must land exactly on the absent bytes
    -- and the absent hash. This is the case that proves omission and `null` are
    -- not interchangeable — they canonicalize differently and therefore chain
    -- to different hashes, exactly as `parents: []` and an absent `parents` do.
    local null_case = case_named("root_commit_sha_null_is_not_absent")
    assert.is_not_nil(null_case)
    assert.equals(absent.canonical_json, core_json.canonicalize(build(null_case).data))
    assert.are_not.equals(absent.canonical_json, null_case.canonical_json)
    assert.are_not.equals(absent.hash, null_case.hash)

    local e = absent.envelope
    assert.equals(
      absent.hash,
      hc
        .chain_entry(absent.prev_hash, envelope.new(e.seq, e.t, e.wall, e.kind, build(null_case).data))
        .hash
    )
  end)

  it("WRITER RULE: a repository path and a remote URL can never reach a payload", function()
    -- S14(b). The shape check is the one place a nonconforming writer's path or
    -- URL is stopped before it reaches a staff-facing UI, and running it on the
    -- WRITE side means such a value is never written down at all. Driven
    -- through the builder, not through the reader, because the reader passing
    -- is not the property under test here.
    local view = git_payloads.commit_view(("b"):rep(40), { ("a"):rep(40) })
    for _, bad in ipairs({
      "/Users/student/cs61b/proj2",
      "C:\\Users\\student\\proj2",
      "git@github.com:acme/cs61b-proj2.git",
      "https://github.com/acme/cs61b-proj2",
      ("A"):rep(40),
      ("a"):rep(39),
      ("a"):rep(41),
      ("a"):rep(63),
      ("a"):rep(65),
      "9999999",
      "",
      "  " .. ("a"):rep(38),
    }) do
      local data = git_payloads.build_git_event("commit", ("b"):rep(40), view, "main", bad).data
      assert.is_nil(data.root_commit_sha, "must omit: " .. bad)
    end
    -- ...while both legal object-name lengths survive verbatim.
    for _, good in ipairs({ ("9"):rep(40), ("8"):rep(64) }) do
      local data = git_payloads.build_git_event("commit", ("b"):rep(40), view, "main", good).data
      assert.equals(good, data.root_commit_sha)
    end
  end)

  it("WRITER RULE: a payload that names no commit carries no discriminator", function()
    -- Rule 10 rides the field on every payload that carries a `sha` — but an
    -- `operation_only` payload names no commit, so there is nothing for a
    -- repository key to key. Pinned so the pre-D12 `operation_only` bytes are
    -- unreachable-by-accident rather than merely untested.
    local data = git_payloads.build_git_event("state_change", nil, nil, nil, ("9"):rep(40)).data
    assert.is_nil(data.root_commit_sha)
    local operation_only = case_named("operation_only")
    assert.is_not_nil(operation_only)
    assert.equals(operation_only.canonical_json, core_json.canonicalize(data))
  end)

  it("WRITER RULE: the discriminator rides on non-commit operations too", function()
    -- An unlabelled observation does not correlate even when its neighbours in
    -- the same session do, so the field is NOT gated on `operation == "commit"`.
    local view = git_payloads.commit_view(("b"):rep(40), nil)
    local data =
      git_payloads.build_git_event("state_change", ("b"):rep(40), view, "main", ("9"):rep(40)).data
    assert.equals(("9"):rep(40), data.root_commit_sha)
  end)

  it("adding the discriminator to a payload MUST change its hash", function()
    -- `root_commit_sha_recorded` is `ordinary_commit` plus the field. A port
    -- that silently dropped an unrecognised argument would produce the other
    -- one's bytes and the other one's hash, and every other assertion in this
    -- file would still pass.
    local plain, labelled = case_named("ordinary_commit"), case_named("root_commit_sha_recorded")
    assert.is_not_nil(plain)
    assert.is_not_nil(labelled)
    assert.are_not.equals(
      core_json.canonicalize(build(plain).data),
      core_json.canonicalize(build(labelled).data)
    )
    assert.are_not.equals(plain.hash, labelled.hash)
    -- ...and JCS places the new key where the vector says: after `parents`,
    -- before `sha`.
    local order = {}
    for k in core_json.canonicalize(build(labelled).data):gmatch('"([%a_]+)":') do
      order[#order + 1] = k
    end
    assert.same(
      { "branch", "commit_sha", "operation", "parents", "root_commit_sha", "sha" },
      order
    )
  end)

  it("IRB (CPHS 2026-06-19796): no vector case carries author identity, and none can", function()
    -- Named explicitly, not just covered by the loop above: the absence of git
    -- author name / email is a protocol commitment. The approved protocol treats
    -- a new category of identifier as requiring a filed modification BEFORE
    -- implementation, so a port that "helpfully" added one would be out of
    -- protocol even though every hash above would still match.
    for _, case in ipairs(fx.cases) do
      local serialized = core_json.canonicalize(build(case).data)
      assert.is_nil(serialized:find("author", 1, true), case.name .. " must not mention an author")
      assert.is_nil(serialized:find("@", 1, true), case.name .. " must not contain an email")
      assert.is_nil(serialized:find("message", 1, true), case.name .. " must not carry a commit message")
      for _, k in ipairs(key_set(case.data)) do
        assert.is_true(ALLOWED_KEYS[k] == true, "vector case " .. case.name .. " has key " .. k)
      end
    end
    -- And the builder has no parameter one could arrive through: commit_view
    -- takes exactly (sha, parents) and projects exactly those two.
    assert.same({ "parents", "sha" }, key_set(git_payloads.commit_view("a", { "b" })))
  end)

  it("MANDATORY: `parents: []` and an ABSENT `parents` are different bytes and different hashes", function()
    -- `[]` is a positive claim ("root commit"); absent means "could not read".
    -- A port that collapsed the two — the easy Lua mistake, since an untagged
    -- empty table canonicalizes as `{}` and a nil field vanishes — would report
    -- every unreadable graph as a root commit.
    local root, unknown = case_named("root_commit"), case_named("unknown_parents")
    assert.is_not_nil(root)
    assert.is_not_nil(unknown)

    local root_json = core_json.canonicalize(build(root).data)
    local unknown_json = core_json.canonicalize(build(unknown).data)
    assert.are_not.equals(root_json, unknown_json)
    assert.is_true(root_json:find('"parents":[]', 1, true) ~= nil)
    assert.is_nil(unknown_json:find("parents", 1, true))

    local function hash_of(case, data)
      local e = case.envelope
      return hc.chain_entry(case.prev_hash, envelope.new(e.seq, e.t, e.wall, e.kind, data)).hash
    end
    assert.are_not.equals(hash_of(root, build(root).data), hash_of(unknown, build(unknown).data))
  end)

  it("MANDATORY: `parents` order is never sorted — a flipped merge hashes differently", function()
    -- JCS sorts object KEYS but leaves array ELEMENTS alone, and parents[1] is
    -- the branch merged INTO. Sorting would both invert the meaning of a merge
    -- and change the signed bytes, so the vector pins the flipped order to a
    -- different hash on purpose.
    local a, b = case_named("merge_commit"), case_named("merge_commit_parents_flipped")
    assert.is_not_nil(a)
    assert.is_not_nil(b)
    assert.are_not.equals(a.hash, b.hash)
    assert.are_not.equals(
      core_json.canonicalize(build(a).data),
      core_json.canonicalize(build(b).data)
    )
    -- The already-sorted list and the reversed one must both survive verbatim.
    assert.equals(a.canonical_json, core_json.canonicalize(build(a).data))
    assert.equals(b.canonical_json, core_json.canonicalize(build(b).data))
  end)

  it("`commit_sha` is still emitted alongside `sha` (1.x readers), and the legacy shape still chains", function()
    -- Readers before writers, permanently: 1.x support does not expire
    -- (program spec §9).
    local ordinary = case_named("ordinary_commit")
    assert.is_not_nil(ordinary)
    local data = build(ordinary).data
    assert.equals(data.commit_sha, data.sha)

    -- The pre-S5 payload is the permanent 1.x compatibility anchor: the same
    -- two-field shape must keep canonicalizing and chaining to its historic
    -- bytes with the new optional fields simply absent.
    local legacy = case_named("legacy_1x")
    assert.is_not_nil(legacy)
    local built = git_payloads.build_git_event(legacy.data.operation, legacy.data.commit_sha)
    assert.same({ "commit_sha", "operation" }, key_set(built.data))
    assert.equals(legacy.canonical_json, core_json.canonicalize(built.data))
    local e = legacy.envelope
    assert.equals(
      legacy.hash,
      hc.chain_entry(legacy.prev_hash, envelope.new(e.seq, e.t, e.wall, e.kind, built.data)).hash
    )
  end)

  it("`branch` is a VALUE at a fixed ASCII key — a non-ASCII branch cannot reorder a signed payload", function()
    -- This port's JCS sorts object keys BYTEWISE, which matches JS/Kotlin's
    -- UTF-16 code-unit order only for ASCII (core/json.lua). Branch names are
    -- user-derived, so they must never be keys. Same payload, three branch
    -- names — ASCII, Latin-1 supplement, and a non-BMP emoji (where bytewise
    -- UTF-8 and UTF-16 code-unit order genuinely diverge): the key order of the
    -- canonical output must be identical in all three.
    local nonascii = case_named("branch_non_ascii")
    assert.is_not_nil(nonascii)
    assert.equals(nonascii.canonical_json, core_json.canonicalize(build(nonascii).data))

    local function key_order(branch)
      local view = git_payloads.commit_view(("a"):rep(40), { ("b"):rep(40) })
      local out = core_json.canonicalize(
        git_payloads.build_git_event("checkout", ("a"):rep(40), view, branch).data
      )
      local order = {}
      for k in out:gmatch('"([%a_]+)":') do
        order[#order + 1] = k
      end
      return order
    end

    local ascii_order = key_order("main")
    assert.same({ "branch", "commit_sha", "operation", "parents", "sha" }, ascii_order)
    assert.same(ascii_order, key_order("feature/\195\188ber"))
    assert.same(ascii_order, key_order("\240\159\148\145")) -- U+1F511, non-BMP
  end)

  it("git.event is on the HARD FLOOR: no policy key, so no gate, so no seq hole", function()
    -- The vector's own floor_note says so, and it matters twice over. Product:
    -- the commit graph is the EXCULPATORY evidence that a large insert was a
    -- merge or a checkout rather than a paste, so a course must not be able to
    -- switch it off. Mechanical: suppression happens before an entry is chained
    -- and given a seq, and a seq hole reads to validation check 4 (seq_gaps) as
    -- a deleted entry — a course's privacy setting would become a tamper signal
    -- against the student.
    local on_floor = false
    for _, kind in ipairs(capture_policy.FLOOR_EVENT_KINDS) do
      if kind == "git.event" then
        on_floor = true
      end
    end
    assert.is_true(on_floor, "git.event must be in FLOOR_EVENT_KINDS")
    assert.is_nil(capture_policy.POLICY_GATED_EVENT_KINDS["git.event"])

    -- Adding fields to a floor payload does not make it gateable.
    local all_off = capture_policy.resolve({
      capture = { selection_change = false, focus_change = false, terminal = false },
    })
    assert.is_true(capture_policy.is_event_kind_captured("git.event", all_off))
    assert.is_nil(all_off.capture and all_off.capture.git_event)
  end)
end)

-- ===========================================================================
-- TIER 4.1 PEER WITNESSING — peer-observed.json
-- ===========================================================================
--
-- `peer.observed` is one contributor's signed record of ANOTHER contributor's
-- `.provenance/` log. Generated by the monorepo's
-- tools/export-conformance-vectors.ts and byte-identical to what provcode and
-- provjet consume — never hand-edit it here.
--
-- Every ACCEPTED case is rebuilt THROUGH this port's own builder
-- (`recorder/events/peer_payload.build`, which the write side in
-- `recorder/watch/peer_watcher.lua` also calls) rather than read out of the
-- vector's decoded `data`: the whole point is to pin our CONSTRUCTION — that
-- the three nulls are emitted as keys, that `seq_high: 0` survives, that no
-- identifier can enter — not vim.json.decode's round-trip. Every REJECTED case
-- is driven through this port's narrowing (`core/peer_observed.validate`) and
-- required to produce the vector's own error kind, so a port asserts accept AND
-- reject rather than only the happy path.

local peer_observed = require("provenance.core.peer_observed")
local peer_payload = require("provenance.recorder.events.peer_payload")

describe("conformance: peer-observed.json (Tier 4.1 peer witnessing)", function()
  local fx = load_fixture("peer-observed.json")

  --- Rebuild one vector case's payload through peer_payload.
  ---
  --- `session_id` / `seq_high` / `last_hash` arrive from vim.json.decode as
  --- `vim.NIL` when the vector spells them null, which is exactly the "chain
  --- was not read" input, so it maps to `unread_tip()`. `seq_high == 0` is fed
  --- through verbatim: turning it into an unread tip is the mutation the
  --- `seq_high_zero` case exists to catch.
  local function build(case)
    local d = case.data
    local tip
    if d.session_id == nil or d.session_id == vim.NIL then
      tip = peer_payload.unread_tip()
    else
      local seq_high = d.seq_high
      if seq_high == vim.NIL then
        seq_high = nil
      end
      local last_hash = d.last_hash
      if last_hash == vim.NIL then
        last_hash = nil
      end
      tip = peer_payload.chain_tip(d.session_id, seq_high, last_hash)
    end
    return peer_payload.build(d.file, d.sha256, d.bytes, tip, d.state)
  end

  local function case_named(name)
    for _, c in ipairs(fx.cases) do
      if c.name == name then
        return c
      end
    end
    return nil
  end

  local function key_set(t)
    local keys = {}
    for k in pairs(t) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    return keys
  end

  -- Cases the vector marks `accepted: false`. A conforming WRITER can never
  -- build them either — three are self-contradictory chain-field combinations
  -- the builder's all-or-nothing tip rules out structurally, one is an invented
  -- state, one an uppercased digest — so they are asserted through the READER,
  -- which is the half that has to keep parsing them.
  local function is_rejected(case)
    return case.accepted == false
  end

  -- ACCEPTED by the reader, but carrying bytes a conforming WRITER cannot
  -- produce: `accepted_unknown_extra_key` is a FUTURE recorder's payload, and
  -- forward compatibility runs one way only. It gets its own test below, which
  -- asserts both halves — the reader ignoring the key, and this writer being
  -- structurally unable to add it.
  local WRITER_CANNOT_PRODUCE = { accepted_unknown_extra_key = true }

  it("the vector ships all twelve cases this port must satisfy", function()
    -- Guards against a silently truncated fixture making the loops below pass
    -- by testing nothing.
    assert.equals(12, #fx.cases)
    local accepted, rejected = 0, 0
    for _, c in ipairs(fx.cases) do
      if is_rejected(c) then
        rejected = rejected + 1
      else
        accepted = accepted + 1
      end
    end
    assert.equals(7, accepted)
    assert.equals(5, rejected)
    -- Exactly one accepted case is writer-unproducible; if the exporter ever
    -- adds another, the byte-exact loop above must be told about it rather than
    -- silently skipping it.
    local unproducible = 0
    for _, c in ipairs(fx.cases) do
      if WRITER_CANNOT_PRODUCE[c.name] then
        unproducible = unproducible + 1
      end
    end
    assert.equals(1, unproducible)
  end)

  it("the five states match log-core's PEER_OBSERVED_STATES exactly, in order", function()
    -- Order is asserted, not just membership: the vector publishes the set as a
    -- list and a port that reordered it would still pass a set comparison while
    -- disagreeing with the exporter.
    assert.same(fx.states, peer_observed.STATES)
  end)

  for _, case in ipairs(fx.cases) do
    if not is_rejected(case) and not WRITER_CANNOT_PRODUCE[case.name] then
      it("case '" .. case.name .. "': " .. case.note, function()
        local ev = build(case)
        assert.equals("peer.observed", ev.kind)

        -- Byte-exact JCS of the payload we CONSTRUCTED.
        assert.equals(case.canonical_json, core_json.canonicalize(ev.data))

        -- ...and the chain hash of the whole envelope built around it.
        local e = case.envelope
        assert.equals("peer.observed", e.kind)
        local env = envelope.new(e.seq, e.t, e.wall, e.kind, ev.data)
        assert.equals(case.hash, hc.chain_entry(case.prev_hash, env).hash)

        -- ...and our own reader accepts what our own writer built.
        local narrowed = peer_observed.validate(ev.data)
        assert.is_true(narrowed.ok, case.name)
      end)
    end
  end

  it("the accepted_unknown_extra_key case: the READER ignores it, the WRITER cannot add it", function()
    -- Forward compatibility runs one way only. A newer recorder's extra field
    -- must not make this reader discard the whole witness — but this writer has
    -- no parameter such a field could arrive through, so the case is asserted
    -- against the reader with the vector's own bytes, and against the writer as
    -- an inability to reproduce them.
    local case = case_named("accepted_unknown_extra_key")
    assert.is_not_nil(case)

    local narrowed = peer_observed.validate(case.data)
    assert.is_true(narrowed.ok)
    -- Ignored, never carried onto the narrowed value.
    assert.is_nil(narrowed.value.future_signal)
    assert.same(peer_observed.PAYLOAD_KEYS, key_set(narrowed.value))

    -- The extra key DOES change the canonical bytes, so the builder — which
    -- cannot produce it — lands on the plain `appeared_parsed` bytes instead.
    local plain = case_named("appeared_parsed")
    assert.is_not_nil(plain)
    assert.equals(plain.canonical_json, core_json.canonicalize(build(case).data))
    assert.are_not.equals(case.canonical_json, plain.canonical_json)
    assert.are_not.equals(case.hash, plain.hash)
  end)

  for _, case in ipairs(fx.cases) do
    if is_rejected(case) then
      it("REJECTED case '" .. case.name .. "': " .. case.note, function()
        local narrowed = peer_observed.validate(case.data)
        assert.is_false(narrowed.ok, case.name .. " must be rejected")
        assert.equals(case.error.kind, narrowed.error.kind, case.name)
        if case.error.present ~= nil then
          assert.same(case.error.present, narrowed.error.present, case.name)
        end
        if case.error.absent ~= nil then
          assert.same(case.error.absent, narrowed.error.absent, case.name)
        end
        if case.error.state ~= nil then
          assert.equals(case.error.state, narrowed.error.state, case.name)
        end
        if case.error.field ~= nil then
          assert.equals(case.error.field, narrowed.error.field, case.name)
        end
        -- A rejection is a sentence a human reads in a staff-facing report, so
        -- it has to say something.
        assert.is_true(#peer_observed.describe_shape_error(narrowed.error) > 0)
      end)
    end
  end

  it("MANDATORY: the three nulls are emitted as KEYS — omitting them changes the hash", function()
    -- The single easiest thing to get wrong in Lua, where a table simply cannot
    -- hold `nil` and the key vanishes silently. The unparseable case's canonical
    -- bytes contain all three nulls; a payload with the keys dropped hashes
    -- differently, so a port that omits them produces a log whose entries hash
    -- differently from every other recorder's for the same observation.
    local case = case_named("unparseable_file")
    assert.is_not_nil(case)

    local data = build(case).data
    assert.same(peer_observed.PAYLOAD_KEYS, key_set(data))
    local canon = core_json.canonicalize(data)
    assert.equals(case.canonical_json, canon)
    assert.is_true(canon:find('"last_hash":null', 1, true) ~= nil)
    assert.is_true(canon:find('"seq_high":null', 1, true) ~= nil)
    assert.is_true(canon:find('"session_id":null', 1, true) ~= nil)

    -- A caller handing in a tip that is missing the keys altogether — a bare
    -- `{}`, or nothing at all — still produces the three nulls. This is the
    -- last line of defence: `unread_tip()` spells them, and `build` re-spells
    -- them, so BOTH would have to be broken for a key to go missing.
    for _, bare in ipairs({ {}, "not a table", 42 }) do
      local rebuilt = peer_payload.build(data.file, data.sha256, data.bytes, bare, "unparseable")
      assert.same(peer_observed.PAYLOAD_KEYS, key_set(rebuilt.data))
      assert.equals(case.canonical_json, core_json.canonicalize(rebuilt.data))
    end

    -- The mutation, driven explicitly: drop the three keys and the bytes and
    -- the chain hash both move.
    local omitted = {
      file = data.file,
      sha256 = data.sha256,
      bytes = data.bytes,
      state = data.state,
    }
    assert.are_not.equals(canon, core_json.canonicalize(omitted))
    local e = case.envelope
    assert.are_not.equals(
      case.hash,
      hc.chain_entry(case.prev_hash, envelope.new(e.seq, e.t, e.wall, e.kind, omitted)).hash
    )
  end)

  it("MANDATORY: `seq_high: 0` is a real value, not an absence", function()
    -- A foreign log holding only its `session.start`. A truthiness check —
    -- `if seq_high then` in a language where 0 is falsy, or the `x and x or
    -- NULL` idiom carried over from one — turns the shortest possible honest
    -- witness into a malformed one. This port's builder and reader both compare
    -- against nil/NULL explicitly; here is the proof.
    local case = case_named("seq_high_zero")
    assert.is_not_nil(case)

    local data = build(case).data
    assert.equals(0, data.seq_high)
    assert.equals(case.canonical_json, core_json.canonicalize(data))
    assert.is_true(core_json.canonicalize(data):find('"seq_high":0', 1, true) ~= nil)

    local narrowed = peer_observed.validate(data)
    assert.is_true(narrowed.ok)
    assert.equals(0, narrowed.value.seq_high)

    -- ...and the chain-tip constructor keeps it rather than routing it to the
    -- unread tip, which is where a truthiness bug would send it.
    local tip = peer_payload.chain_tip(("x"):rep(8), 0, ("b"):rep(64))
    assert.equals(0, tip.seq_high)
    assert.is_true(peer_payload.tip_was_read(tip))
  end)

  it("MANDATORY: `unparseable` and a read chain are mutually exclusive, both ways", function()
    -- Correction 5 from the first implementation: "all-null or all-non-null" is
    -- true but incomplete — a port emitting `grew` with all-nulls passes the
    -- narrowing while violating the intent. Every unreadable chain must be
    -- routed to `unparseable`.
    local unread = peer_payload.unread_tip()
    assert.is_false(peer_payload.tip_was_read(unread))

    -- `unparseable` + a read chain: rejected.
    local bad = peer_payload.build(
      "session-x.slog",
      ("a"):rep(64),
      41,
      peer_payload.chain_tip("s", 3, ("b"):rep(64)),
      "unparseable"
    ).data
    local r = peer_observed.validate(bad)
    assert.is_false(r.ok)
    assert.equals("unparseable_with_chain_values", r.error.kind)

    -- ...and the reverse: `unparseable` + all nulls is the ONLY accepted shape
    -- for an unread chain, which is why the watcher may not report `grew` for
    -- one.
    local good =
      peer_payload.build("session-x.slog", ("a"):rep(64), 41, unread, "unparseable").data
    assert.is_true(peer_observed.validate(good).ok)
  end)

  it("MANDATORY: a partially-read chain is unbuildable, not merely rejected", function()
    -- The most dangerous shape this payload can take: it names a session while
    -- committing to nothing any later archive could contradict. The reader
    -- rejects it; the BUILDER cannot express it at all, because `chain_tip` is
    -- all-three-or-none. Both halves are asserted — a reader-only guarantee
    -- would let this port write a witness its own analyzer discards.
    for _, args in ipairs({
      { "s", nil, ("b"):rep(64) },
      { "s", 3, nil },
      { nil, 3, ("b"):rep(64) },
      { "", 3, ("b"):rep(64) },
    }) do
      local tip = peer_payload.chain_tip(args[1], args[2], args[3])
      assert.is_false(peer_payload.tip_was_read(tip))
      local data = peer_payload.build("f.slog", ("a"):rep(64), 1, tip, "unparseable").data
      assert.is_true(peer_observed.validate(data).ok)
      assert.equals(core_json.NULL, data.session_id)
      assert.equals(core_json.NULL, data.seq_high)
      assert.equals(core_json.NULL, data.last_hash)
    end
  end)

  it("NO IDENTITY: no case carries one, and the builder has no parameter for one", function()
    -- The payload names a FILE and a CHAIN POSITION. This one is about somebody
    -- ELSE, so the CPHS constraint (2026-06-19796) that keeps author identity
    -- out of `git.event` applies with more force. Enforced structurally: the
    -- key set is closed, and `build` reads the tip by name rather than merging
    -- it, so a table handed in carrying an identifier contributes nothing.
    for _, case in ipairs(fx.cases) do
      for _, k in ipairs(key_set(case.data)) do
        local known = k == "future_signal"
        for _, allowed in ipairs(peer_observed.PAYLOAD_KEYS) do
          if k == allowed then
            known = true
          end
        end
        assert.is_true(known, "vector case " .. case.name .. " has unexpected key " .. k)
      end
    end

    local smuggled = {
      session_id = "s",
      seq_high = 1,
      last_hash = ("b"):rep(64),
      student_ref = "0000-1111",
      author_email = "student@example.edu",
      absolute_path = "/Users/student/cs61b/.provenance/session-x.slog",
    }
    local data = peer_payload.build("session-x.slog", ("a"):rep(64), 10, smuggled, "appeared").data
    assert.same(peer_observed.PAYLOAD_KEYS, key_set(data))
    local serialized = core_json.canonicalize(data)
    assert.is_nil(serialized:find("student_ref", 1, true))
    assert.is_nil(serialized:find("@", 1, true))
    assert.is_nil(serialized:find("/Users/", 1, true))
  end)

  it("peer.observed is on the HARD FLOOR: no policy key, so no gate, so no seq hole", function()
    -- The vector's own floor_note says so. Mechanically it matters because
    -- suppression happens before an entry is chained and given a seq, and a seq
    -- hole reads to validation check 4 (seq_gaps) as a DELETED ENTRY.
    --
    -- The placement is provisional by the vector's own words — collaboration
    -- spec §8 item 5 is open — and if it comes back requiring a per-course off
    -- switch the monorepo moves the entry and reissues this vector. Until then
    -- a port must match what the vector publishes, which this asserts.
    local on_floor = false
    for _, kind in ipairs(capture_policy.FLOOR_EVENT_KINDS) do
      if kind == "peer.observed" then
        on_floor = true
      end
    end
    assert.is_true(on_floor, "peer.observed must be in FLOOR_EVENT_KINDS")
    assert.is_nil(capture_policy.POLICY_GATED_EVENT_KINDS["peer.observed"])

    local all_off = capture_policy.resolve({
      capture = { selection_change = false, focus_change = false, terminal = false },
    })
    assert.is_true(capture_policy.is_event_kind_captured("peer.observed", all_off))
    assert.is_nil(all_off.capture and all_off.capture.peer_observation)
  end)
end)

-- ===========================================================================
-- S3 ROLLING SEAL — rolling-manifest.json
-- ===========================================================================
--
-- Every case below is built THROUGH the recorder's own builder
-- (`core/rolling_manifest.build`, which the write side in
-- `recorder/io/rolling_seal_writer.lua` also calls) and only then compared to
-- the vector. Reading the fixture's decoded payload back and re-signing it
-- would pin the JSON round-trip rather than the construction the recorder
-- actually performs — the bug class these vectors exist to catch.
describe("conformance: rolling-manifest.json (S3 rolling seal, format_version 1.2)", function()
  local fx = load_fixture("rolling-manifest.json")
  local rolling = require("provenance.core.rolling_manifest")

  -- The session key the monorepo's exporter signs these vectors with:
  -- `seed(6)`, i.e. 32 bytes of 0x06. Reproducing the SIGNATURE (not merely
  -- verifying it) is what proves this port signs the same message with the
  -- same key derivation, so the private key has to be reconstructed here.
  local SESSION_PRIV = string.rep("\6", 32)

  -- Turn the fixture's decoded manifest into builder input. Deliberately field
  -- by field: the builder's job is to assemble exactly these keys, so handing
  -- it the decoded object wholesale would let a missing key pass unnoticed.
  local function builder_input(m, final)
    local s = m.sessions[1]
    local files = {}
    for i, f in ipairs(m.submission_files) do
      files[i] = { path = f.path, status = f.status, sha256 = f.sha256 }
    end
    return {
      assignment_id = m.assignment_id,
      semester = m.semester,
      extension_hash = m.extension_hash,
      session_id = s.session_id,
      prev_session_id = s.prev_session_id,
      slog_sha256 = s.slog_sha256,
      meta_sha256 = s.meta_sha256,
      submission_files = files,
      final = final,
    }
  end

  it("the vector set is complete (a truncated fixture cannot pass vacuously)", function()
    assert.equals("1.2", fx.format_version)
    assert.equals("1.2", rolling.FORMAT_VERSION)
    assert.equals(5, #fx.not_rolling_filenames)
    assert.equals(4, #fx.rejects)
    assert.equals(5, #fx.final_marker.not_final_values)
    assert.is_table(fx.final_marker.non_final)
    assert.is_table(fx.final_marker["final"])
    assert.is_table(fx.final_marker.downgrade_rejects)
    assert.equals(1, #fx.manifest.sessions)
    assert.equals(2, #fx.manifest.submission_files)
  end)

  it("filenames() reproduces the vector's per-session names", function()
    local names = rolling.filenames(fx.session_id)
    assert.equals(fx.filenames.json, names.json)
    assert.equals(fx.filenames.sig, names.sig)
  end)

  it("parse_filename() round-trips its own output", function()
    for _, part in ipairs({ "json", "sig" }) do
      local parsed = rolling.parse_filename(fx.filenames[part])
      assert.is_table(parsed)
      assert.equals(fx.session_id, parsed.session_id)
      assert.equals(part, parsed.part)
    end
  end)

  it("parse_filename() refuses every name that is NOT a rolling seal", function()
    -- manifest.json / manifest.sig are the CLASSIC seal. A rolling reader that
    -- accepted them would apply single-session rules to a multi-session file;
    -- a rolling WRITER that could spell them would overwrite a signed classic
    -- bundle. Both directions are closed by the same pattern.
    for _, name in ipairs(fx.not_rolling_filenames) do
      assert.is_nil(rolling.parse_filename(name), name .. " must not parse as a rolling seal")
    end
  end)

  it("build() + to_canonical() reproduces the vector's canonical_json byte for byte", function()
    local built = rolling.build(builder_input(fx.manifest, nil))
    assert.equals(fx.canonical_json, bundle.to_canonical(built))
  end)

  it("build() + sign() reproduces the vector's signature with the session key", function()
    local built = rolling.build(builder_input(fx.manifest, nil))
    local signed = bundle.sign(built, SESSION_PRIV)
    assert.equals(fx.canonical_json, signed.canonical_json)
    assert.equals(fx.signature_hex, signed.signature_hex)
    assert.is_true(bundle.verify_sig(signed.canonical_json, signed.signature_hex, fx.session_pubkey_hex))
  end)

  it("the session key we sign with is the one session.start would publish", function()
    assert.equals(fx.session_pubkey_hex, ed25519.to_hex(ed25519.public_key_of(SESSION_PRIV)))
  end)

  it("validate_shape accepts a 1.2 rolling manifest", function()
    local shape = bundle.validate_shape(fx.manifest)
    assert.is_true(shape.ok, vim.inspect(shape.error))
  end)

  it("validate_session_manifest accepts the vector for its own session id", function()
    local ok = rolling.validate_session_manifest(fx.manifest, fx.session_id)
    assert.is_true(ok.ok)
  end)

  it("validate_session_manifest rejects each vector with its documented kind", function()
    for _, case in ipairs(fx.rejects) do
      local res = rolling.validate_session_manifest(case.manifest, case.expected_session_id or fx.session_id)
      assert.is_false(res.ok, case.note)
      assert.equals(case.error_kind, res.error.kind, case.note)
      assert.is_string(rolling.describe_error(res.error))
    end
  end)

  -- --- the `final` marker ---------------------------------------------------

  it("a NON-final roll omits the key entirely — never final = false", function()
    local case = fx.final_marker.non_final
    local built = rolling.build(builder_input(case.manifest, nil))

    -- The key is absent from the built value, not present-and-false. This is
    -- the whole compatibility contract: the non-final canonical bytes must stay
    -- byte-identical to what 1.2 emitted before `final` existed, because three
    -- implementations pin them.
    assert.is_nil(built["final"])
    assert.is_nil(string.find(case.canonical_json, "final", 1, true))

    local signed = bundle.sign(built, SESSION_PRIV)
    assert.equals(case.canonical_json, signed.canonical_json)
    assert.equals(case.signature_hex, signed.signature_hex)
    assert.is_false(rolling.is_final(built))
    assert.is_false(case.is_final)
  end)

  it("`final = false` is NOT how a non-final roll is spelled", function()
    -- Passing false explicitly must produce the identical non-final bytes.
    -- Writing `"final":false` instead would change the signed message and break
    -- every other implementation's byte comparison.
    local built = rolling.build(builder_input(fx.manifest, false))
    assert.is_nil(built["final"])
    assert.equals(fx.final_marker.non_final.canonical_json, bundle.to_canonical(built))
  end)

  it("the FINAL roll carries final = true inside the SIGNED payload", function()
    local case = fx.final_marker["final"]
    local built = rolling.build(builder_input(case.manifest, true))
    assert.is_true(built["final"])

    local signed = bundle.sign(built, SESSION_PRIV)
    assert.equals(case.canonical_json, signed.canonical_json)
    assert.equals(case.signature_hex, signed.signature_hex)
    assert.is_true(bundle.verify_sig(signed.canonical_json, signed.signature_hex, fx.session_pubkey_hex))
    assert.is_true(rolling.is_final(built))
    assert.is_true(case.is_final)
  end)

  it("final and non-final are DIFFERENT signed messages", function()
    -- If they were not, `final` would grant whole-file semantics for free.
    assert.are_not.equal(fx.final_marker["final"].canonical_json, fx.final_marker.non_final.canonical_json)
    assert.are_not.equal(fx.final_marker["final"].signature_hex, fx.final_marker.non_final.signature_hex)
    -- Cross-verification must fail in both directions.
    assert.is_false(bundle.verify_sig(
      fx.final_marker.non_final.canonical_json,
      fx.final_marker["final"].signature_hex,
      fx.session_pubkey_hex
    ))
    assert.is_false(bundle.verify_sig(
      fx.final_marker["final"].canonical_json,
      fx.final_marker.non_final.signature_hex,
      fx.session_pubkey_hex
    ))
  end)

  it("stripping `final` while keeping the final signature does not verify", function()
    -- The downgrade a student would try by hand: delete the key, keep the sig.
    local case = fx.final_marker.downgrade_rejects
    assert.is_false(case.verifies)
    assert.is_false(bundle.verify_sig(case.canonical_json, case.signature_hex, fx.session_pubkey_hex))
  end)

  it("is_final() is strictly `== true` — no truthy value promotes a seal", function()
    -- Lua makes this trap sharper than JS: 0 and "" are both truthy here, so a
    -- bare `if m.final then` would let a forged value buy whole-file semantics.
    for _, v in ipairs(fx.final_marker.not_final_values) do
      assert.is_false(rolling.is_final({ final = v }), "value " .. vim.inspect(v) .. " must not read as final")
    end
    assert.is_false(rolling.is_final({}))
    assert.is_true(rolling.is_final({ final = true }))
  end)
end)
