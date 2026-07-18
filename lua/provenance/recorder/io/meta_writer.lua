--- Writer for the `.slog.meta` file (Plan 4). Builds a `SlogMeta` (the
--- session public key, the encrypted session private key, and the signed
--- checkpoints) and persists it atomically. Unlike the append-only `.slog`
--- (see `session_writer.lua`), `.slog.meta` is small, infrequently
--- mutated, and rewritten wholesale on every change — the real analyzer
--- reads this file, so it must never be observed half-written
--- (CLAUDE.md "Atomic writes").
---
--- `create()` persists immediately so a `.slog.meta` with the session
--- pubkey/encrypted privkey exists on disk from session start, even before
--- the first checkpoint. `append_checkpoint()` pushes into the in-memory
--- `checkpoints` array (order-preserving) and rewrites the whole file.
--- Signing itself happens upstream (`core.checkpoint.sign`); this module
--- only persists the already-signed checkpoint.
local atomic_write_file = require("provenance.recorder.io.atomic_write").atomic_write_file
local json = require("provenance.core.json")

local M = {}

--- @param opts table {meta_path, session_id, session_pubkey_hex, encrypted_privkey}
---   `encrypted_privkey` is the table produced by `core.session_keys.encrypt_privkey`
---   ({algorithm, nonce, ciphertext, salt, info}) — stored as-is.
--- @return table mw {append_checkpoint, get_meta, dispose}
function M.create(opts)
  local meta_path = opts.meta_path

  local meta = {
    format_version = "1.0",
    session_id = opts.session_id,
    session_pubkey = opts.session_pubkey_hex,
    encrypted_session_privkey = opts.encrypted_privkey,
    checkpoints = json.array({}),
  }

  local function persist()
    atomic_write_file(meta_path, json.canonicalize(meta))
  end

  -- Written immediately: the meta file exists (with an empty checkpoints
  -- array) from the moment the session starts, not just after the first
  -- checkpoint.
  persist()

  local mw = {}

  --- Append an already-signed checkpoint ({seq, hash, sig}, as produced by
  --- `core.checkpoint.sign`) and atomically rewrite the whole meta file.
  --- Appends are ordered: array push preserves insertion order.
  --- @param cp table {seq, hash, sig}
  function mw.append_checkpoint(cp)
    meta.checkpoints[#meta.checkpoints + 1] = cp
    persist()
  end

  --- @return table  the in-memory SlogMeta (for tests/introspection)
  function mw.get_meta()
    return meta
  end

  --- No-op: the meta file is always fully written after each mutation
  --- (create()/append_checkpoint() both persist synchronously), so there is
  --- nothing to flush or close. Provided for teardown symmetry with other
  --- writers (CLAUDE.md "every ... has a dispose()").
  function mw.dispose() end

  return mw
end

return M
