--- Per-course student key cache (program spec §S2).
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
local sha256 = require("provenance.core.sha256")
local student_keys = require("provenance.core.student_keys")

local M = {}

--- @param opts table|nil { derive?: function(master_secret, course_id) -> keypair }
---   `derive` is an injection seam for tests; production uses
---   student_keys.derive_course_keypair.
--- @return table cache { get, dispose, _size }
function M.new(opts)
  opts = opts or {}
  local derive = opts.derive or student_keys.derive_course_keypair

  -- "<master fingerprint>:<course_id>" -> { private_key, public_key_hex }
  local entries = {}
  local disposed = false

  local cache = {}

  --- Derive (or return a cached) per-course keypair.
  --- @param master_secret string  32 raw bytes
  --- @param course_id string
  --- @return table|nil keypair, string|nil err  never throws
  function cache.get(master_secret, course_id)
    if type(master_secret) ~= "string" or type(course_id) ~= "string" or course_id == "" then
      return nil, "invalid_input"
    end

    local fingerprint_ok, fingerprint = pcall(sha256.hex, master_secret)
    if not fingerprint_ok then
      return nil, "fingerprint_failed"
    end
    local key = fingerprint .. ":" .. course_id

    if not disposed then
      local hit = entries[key]
      if hit ~= nil then
        return hit
      end
    end

    local ok, keypair = pcall(derive, master_secret, course_id)
    if not ok then
      return nil, tostring(keypair)
    end

    -- A disposed cache still derives (callers must keep working); it just stops
    -- retaining, so no private key outlives teardown.
    if not disposed then
      entries[key] = keypair
    end
    return keypair
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
