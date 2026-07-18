--- Placeholder extension_hash (Plan 4 stand-in for Plan 9).
---
--- The real value is a sha256 tree-hash over this plugin's own source tree
--- (lua/, plugin/) — the value stored in `session.start.recorder` / the
--- bundle manifest's `extension_hash` field and checked against the
--- analyzer's `known-good-extension-hashes.json` allowlist (design.md §8,
--- §6). That computation (walking the source tree, hashing deterministically)
--- is Plan 9's job.
---
--- Until then, `seal.lua` and any other caller needing an extension_hash use
--- this fixed, deliberately-recognizable placeholder so the seal wiring and
--- its tests aren't blocked on tree-hash infra. Pure function, no I/O, no
--- Neovim API — swap the implementation, not the call sites, when Plan 9
--- lands.
local M = {}

-- Recognizable dev placeholder: 64 lowercase hex chars ("ab" repeated 32x).
local DEV_EXTENSION_HASH = ("ab"):rep(32)

--- @return string  64-char lowercase hex digest (fixed placeholder)
function M.compute()
  return DEV_EXTENSION_HASH
end

return M
