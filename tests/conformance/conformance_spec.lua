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
