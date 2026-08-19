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
    -- A wrong-version artifact is refused as not_enrollment_2_0, never as a bad
    -- signature -- otherwise a future 3.0 could be walked under 2.0 rules.
    for _, name in ipairs({ "cert_not_2_0", "token_not_2_0" }) do
      local case
      for _, c in ipairs(fx.chain_cases) do
        if c.name == name then case = c end
      end
      assert.is_not_nil(case)
      assert.equals("not_enrollment_2_0", case.expected.error.kind)
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

describe("conformance: git-event.json (program spec S5 — the commit graph)", function()
  local fx = load_fixture("git-event.json")

  -- The five structural keys, and NOTHING else, may ever appear in a
  -- git.event payload. Author identity is not on this list and never will be.
  local ALLOWED_KEYS = { operation = true, commit_sha = true, sha = true, parents = true, branch = true }

  --- Rebuild one vector case's payload through git_payloads.
  --- `data.parents` absent (nil) and `data.parents == []` (an empty Lua table
  --- from vim.json.decode) are the two DIFFERENT inputs the vector exists to
  --- distinguish, so presence is tested with `~= nil`, never with `#`.
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
    return git_payloads.build_git_event(d.operation, d.commit_sha, view, d.branch)
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

  it("the vector ships all eleven cases this port must satisfy", function()
    -- Guards against a silently truncated fixture making the loop below pass
    -- by testing nothing.
    assert.equals(11, #fx.cases)
  end)

  for _, case in ipairs(fx.cases) do
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
