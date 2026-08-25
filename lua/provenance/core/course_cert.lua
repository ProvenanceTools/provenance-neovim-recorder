--- Course certificate — the middle link of the Manifest 2.0 trust chain.
--- Lua port of log-core's `course-cert.ts`; program spec §2/§3
--- (2026-08-18-multicourse-program-architecture).
---
---   root keypair (Provenance maintainer, offline; NEVER signs a manifest)
---        | signs
---        v
---   course_cert { course_id, course_pubkey, valid_from, valid_until }
---        | authorizes
---        v
---   course keypair (course staff; signs `.provenance-manifest` files)
---
--- **The root public key is never a constant in this module.** It is embedded
--- by the recorder build and passed to `verify` as a parameter, exactly as in
--- log-core. A hardcoded key here would make one build serve exactly one
--- deployment, which is the thing this design exists to remove.
---
--- The signed payload is the certificate MINUS `root_sig`:
---
---   canonicalize({course_id, course_pubkey, valid_from, valid_until})
---
--- Revocation is deliberately NOT modelled: an offline recorder cannot learn
--- that a key was revoked without a network call, which recorder PRD NG2
--- forbids. Revocation is a server-side list keyed on `course_pubkey` (not on
--- certificate identity — the cert sits outside the course-signed payload, so
--- the student chooses which of their course's certs ships). The offline
--- mitigation is short validity windows. A real, accepted limitation.
---
--- ## Permanent constraint: no user-derived object keys in a signed payload
---
--- Every object KEY that ends up inside a canonicalized, signed payload MUST be
--- a fixed ASCII identifier chosen by us — never a course id, student ref,
--- filename, or other user-supplied string promoted to a key. This module's
--- four keys are all fixed ASCII. The reason is acute in *this* repo:
--- `core/json.lua` sorts object keys BYTEWISE, while the JS (`canonicalize`)
--- and Kotlin (`java-json-canonicalization`) implementations sort by UTF-16
--- code unit. Those orderings agree for ASCII and diverge above U+007F,
--- silently producing different signed bytes. Values are unconstrained.
---
--- Pure: no Neovim editor APIs, no I/O. Nothing here throws — every entry
--- point is a value-returning function with pcall-wrapped crypto.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local ed25519 = require("provenance.core.ed25519")

local M = {}

local function is_nonempty_string(v)
  return type(v) == "string" and v ~= ""
end

local function is_hex(v, n)
  return type(v) == "string" and #v == n and v:match("^[0-9a-f]+$") ~= nil
end

-- ---------------------------------------------------------------------------
-- Timestamp parsing
-- ---------------------------------------------------------------------------

local DAYS_IN_MONTH = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }

local function is_leap_year(y)
  return (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0
end

--- Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard
--- Hinnant's `days_from_civil`). Hand-rolled because Lua's `os.time` is
--- local-time and 32-bit-limited on some builds, and the reference parser is
--- specified entirely in UTC.
local function days_from_civil(y, m, d)
  local yy = y - (m <= 2 and 1 or 0)
  local era = math.floor(yy / 400)
  local yoe = yy - era * 400
  local doy = math.floor((153 * (m + (m > 2 and -3 or 9)) + 2) / 5) + d - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

--- Parse an ISO 8601 timestamp to epoch milliseconds, or nil if it does not
--- match the grammar. Hand-parsed rather than delegated to any date library so
--- the three implementations share one accepting set — `Date.parse` accepts a
--- large implementation-defined superset, `java.time` a different one, and Lua
--- has no date parser at all.
---
--- Grammar (log-core's ISO_INSTANT_RE):
---   YYYY-MM-DD [ THH:MM:SS [ .fraction(1-9 digits) ] [ Z | +HH:MM | -HH:MM ] ]
---
--- Deliberate rules, all pinned by `timestamp_parse_cases`:
---  - A **date-only** string is UTC midnight that day, i.e. its FIRST instant.
---    That is the right reading for `valid_from`, and this function keeps it
---    for every caller. `valid_until` is the one exception and it is applied by
---    the CALLER, not here: see M.resolve_valid_until_exclusive_ms, which
---    extends a date-only upper bound through the end of that day.
---  - A timestamp with **no offset** is UTC.
---  - Fractional seconds are padded/truncated to exactly 3 digits (ms).
---  - `second > 59` rejects leap seconds and `hour > 23` rejects the
---    legal-ISO `24:00:00`; `java.time` accepts both and `Date` does not, so
---    the parser normalises the difference away by rejecting.
---  - Non-existent calendar dates (2026-02-31, 2027-02-29) are REJECTED, not
---    rolled forward as JS `Date` would.
--- @param value string
--- @return number|nil  epoch milliseconds
function M.parse_iso_instant_ms(value)
  if type(value) ~= "string" then
    return nil
  end

  local y, mo, d, rest = value:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)(.*)$")
  if y == nil then
    return nil
  end
  y, mo, d = tonumber(y), tonumber(mo), tonumber(d)

  local hour, minute, second, millis, offset_ms = 0, 0, 0, 0, 0

  if rest ~= "" then
    local hh, mi, ss, tail = rest:match("^T(%d%d):(%d%d):(%d%d)(.*)$")
    if hh == nil then
      return nil
    end
    hour, minute, second = tonumber(hh), tonumber(mi), tonumber(ss)

    local frac, after_frac = tail:match("^%.(%d+)(.*)$")
    if frac ~= nil then
      -- The reference grammar allows 1-9 fractional digits; more is a
      -- non-match, not a truncation.
      if #frac > 9 then
        return nil
      end
      millis = tonumber((frac .. "000"):sub(1, 3))
      tail = after_frac
    end

    if tail ~= "" and tail ~= "Z" then
      local sign, oh, om = tail:match("^([+%-])(%d%d):(%d%d)$")
      if sign == nil then
        return nil
      end
      oh, om = tonumber(oh), tonumber(om)
      if oh > 23 or om > 59 then
        return nil
      end
      -- A "+02:00" wall time is EARLIER in UTC, hence the inverted sign.
      offset_ms = (sign == "-" and 1 or -1) * (oh * 60 + om) * 60000
    end
  end

  if mo < 1 or mo > 12 then
    return nil
  end
  if d < 1 or d > 31 then
    return nil
  end
  if hour > 23 or minute > 59 or second > 59 then
    return nil
  end

  local max_day = DAYS_IN_MONTH[mo]
  if mo == 2 and is_leap_year(y) then
    max_day = 29
  end
  if d > max_day then
    return nil
  end

  local days = days_from_civil(y, mo, d)
  return days * 86400000 + hour * 3600000 + minute * 60000 + second * 1000 + millis + offset_ms
end

local ONE_DAY_MS = 24 * 60 * 60 * 1000

--- Matches ONLY a bare `YYYY-MM-DD` -- no time component at all.
local function is_date_only(value)
  return type(value) == "string" and value:match("^%d%d%d%d%-%d%d%-%d%d$") ~= nil
end

--- Resolve a `valid_until` value to an EXCLUSIVE upper-bound instant, in epoch
--- milliseconds: the certificate is out of window once `issued >= result`.
---
--- `valid_until` is an inclusive upper bound, but a date-only value
--- (`YYYY-MM-DD`) is inclusive **through the end of that day**, not merely its
--- first instant -- "valid until Jan 15" should cover Jan 15. Note the
--- deliberate ASYMMETRY with `valid_from`, which stays inclusive from its day's
--- first instant.
---
--- Expressed as an exclusive bound at the START OF THE NEXT DAY rather than an
--- inclusive `<day-start> + 23:59:59.999`, on purpose: an exclusive
--- next-midnight bound cannot be undercut by a precision trap (a stray
--- leap-second adjustment, a sub-millisecond source, an off-by-one in a port's
--- "last millisecond of the day" arithmetic) the way a literal 23:59:59.999
--- constant could be. Every instant this is compared against is itself parsed
--- to millisecond resolution, so the two framings denote the identical set of
--- in-window instants -- exclusive is chosen for robustness, not behaviour.
---
--- A full timestamp keeps its exact-instant meaning: valid AT that instant,
--- expired the millisecond after, so the exclusive bound is `<parsed ms> + 1`.
---
--- @param value string
--- @return number|nil  epoch milliseconds, exclusive; nil if unparseable
function M.resolve_valid_until_exclusive_ms(value)
  local ms = M.parse_iso_instant_ms(value)
  if ms == nil then
    return nil
  end
  if is_date_only(value) then
    return ms + ONE_DAY_MS
  end
  return ms + 1
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

--- Build the exact byte string the ROOT key signs: the certificate minus
--- `root_sig`, JCS-canonicalized. JCS sorts keys, so the literal order here has
--- no effect on the output.
--- @param cert table
--- @return string
function M.signed_payload(cert)
  return json.canonicalize({
    course_id = cert.course_id,
    course_pubkey = cert.course_pubkey,
    valid_from = cert.valid_from,
    valid_until = cert.valid_until,
  })
end

--- Validate the shape of an already-decoded `course_cert` value. Takes a value
--- rather than text because the certificate travels **inline** inside
--- `.provenance-manifest` (program spec §2): one file to discover, one to
--- distribute, no chance of the two being separated by a copy or a `.gitignore`.
---
--- Unknown keys are ignored for forward compatibility. That is safe:
--- canonicalization operates on the four named fields only, so an unknown key
--- can never silently change the signed bytes.
---
--- The validity bounds must actually PARSE. Program spec §2 names short
--- validity windows as the only mitigation for having no offline revocation, so
--- a bound that silently never binds would undercut the one offline control
--- there is. Certificates are new in 2.0, so there is no archived-manifest
--- compatibility cost to enforcing this (unlike `manifest.issued_at`, which
--- stays lenient because 1.x manifests in the wild predate any such rule).
--- @param value table  an already-decoded (and normalized) JSON value
--- @return table  { ok = true, value = CourseCert } | { ok = false, error = { reason, field? } }
function M.parse(value)
  if type(value) ~= "table" or json.is_array(value) or value == json.NULL then
    return result.err({ reason = "not_object" })
  end

  if not is_nonempty_string(value.course_id) then
    return result.err({ reason = "invalid", field = "course_id" })
  end

  local bounds = {}
  for _, field in ipairs({ "valid_from", "valid_until" }) do
    local v = value[field]
    if not is_nonempty_string(v) then
      return result.err({ reason = "invalid", field = field })
    end
    local ms = M.parse_iso_instant_ms(v)
    if ms == nil then
      return result.err({ reason = "must be an ISO 8601 date or timestamp", field = field })
    end
    bounds[field] = ms
  end
  if bounds.valid_from > bounds.valid_until then
    return result.err({ reason = "must not be earlier than valid_from", field = "valid_until" })
  end

  if not is_hex(value.course_pubkey, 64) then
    return result.err({ reason = "must be 64-char hex", field = "course_pubkey" })
  end

  if value.root_sig == nil then
    return result.err({ reason = "missing", field = "root_sig" })
  end
  if not is_hex(value.root_sig, 128) then
    return result.err({ reason = "must be 128-char hex", field = "root_sig" })
  end

  return result.ok({
    course_id = value.course_id,
    course_pubkey = value.course_pubkey,
    valid_from = value.valid_from,
    valid_until = value.valid_until,
    root_sig = value.root_sig,
  })
end

--- Step 1 of the Manifest 2.0 verification order: verify `course_cert` minus
--- `root_sig` against the embedded root public key.
---
--- @param cert table  a certificate (typically the .value of a successful parse())
--- @param root_pubkey_hex string  64-char hex ed25519 ROOT public key. A
---   PARAMETER, never a constant here — see the module docstring.
--- @return boolean  never throws; false on any malformed input
function M.verify(cert, root_pubkey_hex)
  local ok, verified = pcall(function()
    if type(cert) ~= "table" then
      return false
    end
    if not is_hex(root_pubkey_hex, 64) then
      return false
    end
    if not is_hex(cert.root_sig, 128) then
      return false
    end
    if not is_nonempty_string(cert.course_id) then
      return false
    end
    if not is_nonempty_string(cert.valid_from) or not is_nonempty_string(cert.valid_until) then
      return false
    end
    if not is_hex(cert.course_pubkey, 64) then
      return false
    end
    return ed25519.verify(ed25519.from_hex(cert.root_sig), M.signed_payload(cert), root_pubkey_hex)
  end)
  if not ok then
    return false
  end
  return verified == true
end

--- Step 4 of the Manifest 2.0 verification order: is `issued_at` inside
--- `[valid_from, valid_until]`? **Both bounds inclusive** -- but "inclusive"
--- means different arithmetic at each end for a DATE-ONLY bound: `valid_from`
--- is inclusive from that day's first instant, while `valid_until` is inclusive
--- through that day's last instant (see M.resolve_valid_until_exclusive_ms). A
--- full-timestamp bound at either end means exactly that instant, at
--- millisecond resolution.
---
--- Evaluated against the manifest's `issued_at`, NEVER against wall-clock now:
--- a Fall 2026 bundle must still verify in 2028 for an adjudication case. The
--- question is always "was the cert valid when the manifest was issued".
---
--- Being out of window is NOT fatal and never invalidates a signature — the
--- caller decides (program spec §4: an expired cert must not stop a recorder
--- from recording, because silently halting capture for a whole class is a
--- worse failure for an integrity tool than recording under a stale key).
--- @param cert table
--- @param issued_at string
--- @return table  { in_window = true }
---   | { in_window = false, reason = "before_valid_from" | "after_valid_until" | "unparseable_timestamp" }
function M.check_window(cert, issued_at)
  local from = M.parse_iso_instant_ms(cert.valid_from)
  local until_exclusive = M.resolve_valid_until_exclusive_ms(cert.valid_until)
  local issued = M.parse_iso_instant_ms(issued_at)

  if from == nil or until_exclusive == nil or issued == nil then
    return { in_window = false, reason = "unparseable_timestamp" }
  end
  if issued < from then
    return { in_window = false, reason = "before_valid_from" }
  end
  if issued >= until_exclusive then
    return { in_window = false, reason = "after_valid_until" }
  end
  return { in_window = true }
end

return M
