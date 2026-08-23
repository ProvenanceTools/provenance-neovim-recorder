--- Reading one workspace-relative path's on-disk state, shared by both seals.
---
--- `commands/seal.lua` (the classic seal) and `io/rolling_seal_writer.lua`
--- (the rolling seal) each need to answer the exact same question for a
--- candidate path — present-with-hash, genuinely absent, unreadable, or
--- resolved outside the workspace — and answer it the exact same way, or the
--- two seals of the same session can disagree about a file's status. This
--- module is the ONE implementation both are meant to import.
---
--- Port of the monorepo's `packages/recorder/src/io/workspace-file-read.ts`
--- (`resolveContainment` / `readWorkspaceFile`). See that file's docstrings
--- for the full reasoning; this file carries it across statement-for-
--- statement, adapted to `vim.uv`.
---
--- ## Why `missing` is reachable from exactly ONE condition
---
--- `missing` is an AFFIRMATIVE claim about the student — "this file was
--- named and is not there" — rendered to staff as "File listed in
--- files_under_review but absent on disk at seal time" and used in
--- academic-integrity proceedings. Emitting one about a file the student
--- actually submitted is the worst failure this system can produce (this
--- cost four fix rounds on the monorepo's classic seal to close completely).
--- So `missing` may only be minted for the ONE errno that actually means
--- "this file does not exist": ENOENT, from the containment check, the
--- regular-file stat, or the final read. Every other outcome — a permission
--- error, a directory where a file was expected, a symlink cycle, a
--- non-regular file (a FIFO would block a read forever with no timeout
--- anywhere in this call stack) — is `unreadable` instead: the file's
--- existence is either known-true or simply undetermined, and reporting
--- `missing` for any of those would be a false claim.
---
--- `out_of_workspace` is its own, third outcome, never folded into `missing`
--- either: a path that resolves — after following every symlink — outside
--- the workspace root is not "absent", it is "there, and we refuse to read
--- it because we cannot vouch for where it points". The overwhelmingly
--- common way to reach this is not an attack: a student's
--- `ln -s ~/shared/data.csv data.csv`, with `data.csv` an exact `track`
--- entry. Minting `missing` for that told staff "the student didn't submit
--- it" about a file sitting on disk and fully readable.
---
--- Callers are responsible for the SECOND half of the invariant: only an
--- EXACT `scope.track`/`files_under_review` entry may ever turn a `missing`
--- result from here into a submission-files record with status `missing` —
--- a rule entry (`src/`, `*.java`) asserts nothing about any particular file
--- existing, so a rule-matched path this module reports `missing` for (i.e.
--- vanished between the walk sighting it and the read here) must be DROPPED
--- by the caller, never recorded.
---
--- Pure I/O over vim.uv; no other Neovim editor API.
local core_sha256 = require("provenance.core.sha256")
local core_json = require("provenance.core.json")

local M = {}

-- ---------------------------------------------------------------------------
-- Small local helpers
-- ---------------------------------------------------------------------------

local function starts_with(s, prefix)
  return s:sub(1, #prefix) == prefix
end

-- ---------------------------------------------------------------------------
-- resolve_containment
-- ---------------------------------------------------------------------------

--- Where `abs_path` really sits relative to `real_root`, after resolving ALL
--- symlinks on BOTH sides.
---
--- Both sides must be realpath'd, not just one: realpathing only `abs_path`
--- would still miss the actual escape this exists for — a symlink INSIDE the
--- workspace (e.g. `out.txt`) whose target resolves OUTSIDE it — because a
--- lexically-inside symlink only reveals where it really points once ITS OWN
--- link is followed. And realpathing only `abs_path` while comparing against
--- the LEXICAL root would reject every path in a perfectly ordinary macOS
--- workspace: `/var/folders/...` (this module's own test fixtures) is itself
--- a symlink to `/private/var/folders/...`, so the root's own lexical and
--- real forms already disagree before any workspace file is considered.
---
--- FAILS CLOSED: `unresolved` must NOT let the read proceed against an
--- unverified path. A security check should not default to "allow" on
--- error. Failing closed costs nothing real, because of a syscall
--- equivalence: `realpath(p)` and reading `p` walk the same path with the
--- same resolution rules and the same permission checks, so whenever
--- `realpath` fails, the read fails with the identical errno. `unresolved`
--- therefore carries that errno (`code`) up, and `read_workspace_file`
--- classifies it EXACTLY as it would have classified the read's own
--- failure: ENOENT -> `missing` (the file genuinely is not there, and there
--- is no target outside the root to leak), anything else -> `unreadable`.
---
--- `real_root` should be precomputed ONCE per seal call, not realpath'd
--- again on every call here — both seals bound how many files reach this
--- check to "in-scope files", not "everything under the root", so the
--- per-call cost is one `fs_realpath` for `abs_path` plus a string
--- comparison.
---
--- "inside" means `real_path == real_root` or `real_path` starts with
--- `real_root .. "/"` — a bare prefix test would let `/ws` wrongly contain
--- `/wsother`.
---
--- Verified empirically (see task report): `vim.uv.fs_realpath` on failure
--- returns `nil, message, name`, where `name` is the bare errno string
--- (`"ENOENT"`, `"EACCES"`, ...) — that is what `code` below is.
---
--- @param real_root string
--- @param abs_path string
--- @return table { kind = "inside" } | { kind = "outside" } | { kind = "unresolved", code = string|nil }
function M.resolve_containment(real_root, abs_path)
  local uv = vim.uv or vim.loop
  local real_path, _msg, code = uv.fs_realpath(abs_path)
  if real_path == nil then
    return { kind = "unresolved", code = code }
  end
  if real_path == real_root or starts_with(real_path, real_root .. "/") then
    return { kind = "inside" }
  end
  return { kind = "outside" }
end

-- ---------------------------------------------------------------------------
-- read_workspace_file
-- ---------------------------------------------------------------------------

--- Read one workspace-relative path's on-disk state: present-with-hash,
--- missing (ENOENT only), unreadable (any other read failure), or
--- out-of-workspace (resolves, after following every symlink, outside the
--- workspace root). `rel_path` is resolved against `workspace_root`;
--- `workspace_real_root` is `workspace_root` with all symlinks already
--- resolved (see `M.resolve_containment`).
---
--- `opts.with_bytes = true` (the classic seal's ZIP step needs the raw
--- bytes) attaches them to the `present` case as `bytes`; omitted or false
--- (the rolling seal only ever needs the hash) OMITS the key entirely —
--- never `bytes = nil` — because this result is spread into a
--- JCS-canonicalized SIGNED manifest and a stray key shifts the signed
--- bytes. See this module's docstring for the full "why `missing` is
--- reachable from exactly one condition" reasoning.
---
--- @param workspace_root string
--- @param workspace_real_root string
--- @param rel_path string
--- @param opts table|nil { with_bytes: boolean|nil }
--- @return table one of:
---   { path, status = "present", sha256 = <64 hex>, bytes = <string, only when with_bytes> }
---   { path, status = "missing", sha256 = <core_json.NULL> }
---   { path, status = "unreadable" }
---   { path, status = "out_of_workspace" }
function M.read_workspace_file(workspace_root, workspace_real_root, rel_path, opts)
  opts = opts or {}
  local with_bytes = opts.with_bytes == true
  local uv = vim.uv or vim.loop
  local abs = workspace_root .. "/" .. rel_path

  local containment = M.resolve_containment(workspace_real_root, abs)
  if containment.kind == "outside" then
    -- Never `missing` — see this module's docstring. A path the walk itself
    -- produced can never trip this: it is always built from real
    -- (non-symlink) directory entries under `workspace_root`, all the way
    -- down (see `workspace_walk.lua`). Only a manifest-supplied EXACT entry,
    -- read directly by string, can land here.
    return { path = rel_path, status = "out_of_workspace" }
  end
  if containment.kind == "unresolved" then
    -- Fail closed: the path was NOT verified, so it is not opened. Classify
    -- it exactly as the read itself would have — see `M.resolve_containment`'s
    -- docstring for the syscall equivalence that makes this lossless.
    if containment.code == "ENOENT" then
      return { path = rel_path, status = "missing", sha256 = core_json.NULL }
    end
    return { path = rel_path, status = "unreadable" }
  end

  -- containment.kind == "inside" from here down.
  --
  -- Only a REGULAR file may be read. Reading a FIFO BLOCKS FOREVER waiting
  -- for a writer, with no timeout anywhere in this call stack: a student who
  -- does `rm Main.java && mkfifo Main.java` (`Main.java` being an exact
  -- `track` entry, and FIFOs being invisible to the walk's own file check)
  -- would hang the whole seal. `fs_stat` never blocks on a FIFO — only
  -- `fs_open` (for read) does — so this gate is safe to take first. It also
  -- gives directories (an ordinary staff manifest typo naming `src` instead
  -- of `src/`) a cleaner home than catching EISDIR off the read, and covers
  -- sockets, devices, and block specials for free. `fs_stat` follows
  -- symlinks (verified empirically), matching the read's own semantics, so
  -- a symlink to a regular file inside the workspace still passes.
  local st, _stat_msg, stat_code = uv.fs_stat(abs)
  if st == nil then
    if stat_code == "ENOENT" then
      return { path = rel_path, status = "missing", sha256 = core_json.NULL }
    end
    return { path = rel_path, status = "unreadable" }
  end
  if st.type ~= "file" then
    return { path = rel_path, status = "unreadable" }
  end

  local fd, _open_msg, open_code = uv.fs_open(abs, "r", 438) -- 438 = 0o666
  if fd == nil then
    -- `missing` may only be minted for the one errno that actually means
    -- "this file does not exist": ENOENT. See this module's docstring.
    if open_code == "ENOENT" then
      return { path = rel_path, status = "missing", sha256 = core_json.NULL }
    end
    return { path = rel_path, status = "unreadable" }
  end

  local ok, bytes = pcall(function()
    local fst = uv.fs_fstat(fd)
    if not fst then
      error("fstat failed")
    end
    local chunk = uv.fs_read(fd, fst.size, 0)
    if chunk == nil then
      error("read failed")
    end
    return chunk
  end)
  uv.fs_close(fd) -- always close, on both the success and error paths

  if not ok then
    return { path = rel_path, status = "unreadable" }
  end

  local sha256 = core_sha256.hex(bytes)
  if with_bytes then
    return { path = rel_path, status = "present", sha256 = sha256, bytes = bytes }
  end
  return { path = rel_path, status = "present", sha256 = sha256 }
end

return M
