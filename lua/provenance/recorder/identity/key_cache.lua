--- Student key cache (program spec §S2).
---
--- Caches BOTH derivations: the CURRENT global key (`get_global`, identity 2.1)
--- and the LEGACY per-course key (`get`, identity 2.0). The legacy entry point
--- stays because archived tokens name per-course public keys and a student
--- holding one must keep recording under it.
---
--- `student_keys.derive_course_keypair` costs ~6.3 ms in this pure-Lua port —
--- one HKDF (free) plus one ed25519 public-key computation (everything). That is
--- the same order as a signature verification here, and it is a pure function of
--- `(master_secret, course_id)`, so it should be computed once per course and
--- reused for the life of the editor session.
---
--- ## Why the cache lives HERE and not in `core/`
---
--- `core/student_keys.lua` deliberately does not memoize: `core/` is pure, and a
--- module-level table there would hold a student's derived PRIVATE KEY for the
--- whole process lifetime with no owner and no teardown path. That is strictly
--- worse than the 6 ms it saves.
---
--- This module is the recorder-layer answer, following `registry.lua`'s
--- verified-roots precedent: an instance with exactly one owner
--- (`recorder/init.lua`'s `setup()`) and exactly one disposal path (its
--- `handle.dispose()`), so the keys are dropped when the plugin tears down
--- rather than living until the editor exits.
---
--- ## The cache key includes a master-secret fingerprint
---
--- Keyed on `course_id` PLUS a sha256 fingerprint of the master secret, not
--- `course_id` alone. A student who imports a different master secret mid-session
--- (moving machines, or correcting a bad paste) must not keep getting keys
--- derived from the old one — that would silently produce a countersignature
--- that cannot verify against the token they hold. The fingerprint is a hash, so
--- the cache key never contains the secret itself.
---
--- The global key has no course component, so its entries live under a distinct
--- `GLOBAL_PREFIX` namespace. The two namespaces cannot collide: a per-course key
--- is `<64 hex>:<course_id>`, and no 64-hex run starts with `global:`. Keeping
--- them apart matters — the two derivations use different HKDF `info` strings and
--- produce DIFFERENT keys from the same secret, so a collision would hand a
--- caller the wrong private key and manufacture a countersignature that cannot
--- verify.
local sha256 = require("provenance.core.sha256")
local student_keys = require("provenance.core.student_keys")

local M = {}

--- Namespace for the global (identity 2.1) key. See the collision note above.
local GLOBAL_PREFIX = "global:"

--- @param opts table|nil {
---   derive?: function(master_secret, course_id) -> keypair,
---   derive_global?: function(master_secret) -> keypair,
--- }
---   Both are injection seams for tests; production uses
---   student_keys.derive_course_keypair / student_keys.derive_student_keypair.
--- @return table cache { get, get_global, dispose, _size }
function M.new(opts)
  opts = opts or {}
  local derive = opts.derive or student_keys.derive_course_keypair
  local derive_global = opts.derive_global or student_keys.derive_student_keypair

  -- "<master fingerprint>:<course_id>" -> { private_key, public_key_hex }
  -- "global:<master fingerprint>"      -> { private_key, public_key_hex }
  local entries = {}
  local disposed = false

  local cache = {}

  --- sha256 of the master secret. Never the secret itself.
  --- @return string|nil fingerprint
  local function fingerprint_of(master_secret)
    local ok, fingerprint = pcall(sha256.hex, master_secret)
    if not ok then
      return nil
    end
    return fingerprint
  end

  --- Shared memoize-around-derive. A disposed cache still DERIVES (callers must
  --- keep working); it simply stops retaining, so no private key outlives
  --- teardown.
  local function memoized(key, produce)
    if not disposed then
      local hit = entries[key]
      if hit ~= nil then
        return hit
      end
    end

    local ok, keypair = pcall(produce)
    if not ok then
      return nil, tostring(keypair)
    end

    if not disposed then
      entries[key] = keypair
    end
    return keypair
  end

  --- Derive (or return a cached) GLOBAL student keypair — identity 2.1.
  ---
  --- One key per student, forever, across every course. No course component,
  --- because a 2.1 credential names no course.
  --- @param master_secret string  32 raw bytes
  --- @return table|nil keypair, string|nil err  never throws
  function cache.get_global(master_secret)
    if type(master_secret) ~= "string" then
      return nil, "invalid_input"
    end
    local fingerprint = fingerprint_of(master_secret)
    if fingerprint == nil then
      return nil, "fingerprint_failed"
    end
    return memoized(GLOBAL_PREFIX .. fingerprint, function()
      return derive_global(master_secret)
    end)
  end

  --- Derive (or return a cached) LEGACY per-course keypair — identity 2.0.
  --- Kept live: a token a student already holds must keep working.
  --- @param master_secret string  32 raw bytes
  --- @param course_id string
  --- @return table|nil keypair, string|nil err  never throws
  function cache.get(master_secret, course_id)
    if type(master_secret) ~= "string" or type(course_id) ~= "string" or course_id == "" then
      return nil, "invalid_input"
    end

    local fingerprint = fingerprint_of(master_secret)
    if fingerprint == nil then
      return nil, "fingerprint_failed"
    end
    return memoized(fingerprint .. ":" .. course_id, function()
      return derive(master_secret, course_id)
    end)
  end

  --- Drop every derived key. Idempotent. After this the cache still answers
  --- get() correctly, it simply retains nothing.
  function cache.dispose()
    disposed = true
    entries = {}
  end

  --- Number of retained entries. Test/inspection seam.
  function cache._size()
    local n = 0
    for _ in pairs(entries) do
      n = n + 1
    end
    return n
  end

  return cache
end

return M
