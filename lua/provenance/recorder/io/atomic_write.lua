--- Atomic file write over vim.uv: write-temp-then-rename so a signed,
--- integrity-critical file (`.slog.meta`, `manifest.json`, `manifest.sig`)
--- is never left half-written on disk (design.md; CLAUDE.md "Atomic
--- writes"). Not used for the `.slog` itself, which is append-only.
---
--- No Neovim editor API use beyond the allowed runtime primitives
--- (`vim.uv`), matching the `recorder/` wiring layer's scope.

local M = {}

-- Forward declaration: atomic_write_file and atomic_write_file_pair both call
-- stage(), which is defined after them so each public entry point reads before
-- the primitive it composes.
local stage

-- 8 hex chars of entropy from vim.uv's CSPRNG (falls back to a time+counter
-- seed if random() is ever unavailable — not expected on any supported
-- Neovim, but cheap insurance since the exact temp name is not asserted).
local counter = 0
local function random_hex(uv)
  local bytes = uv.random and uv.random(4) or nil
  if bytes then
    return (bytes:gsub(".", function(c)
      return string.format("%02x", c:byte())
    end))
  end
  counter = counter + 1
  return string.format("%08x", (uv.hrtime() + counter) % 0xffffffff)
end

--- Write `contents` to `target_path` atomically: write to a sibling temp
--- file in the same directory, fsync it for durability, then rename it
--- over the target (atomic on the same filesystem).
---
--- Raises (via `error`) on any unexpected I/O failure — this is the
--- "raised only when unexpected" path per CLAUDE.md, not the never-throw
--- core surface. On failure the original file at `target_path` (if any)
--- is left untouched, and the temp file is best-effort cleaned up.
---
--- @param target_path string
--- @param contents string
--- @return boolean true on success
function M.atomic_write_file(target_path, contents)
  local uv = vim.uv or vim.loop
  local tmp = stage(uv, target_path, contents)

  local renamed, rename_err = uv.fs_rename(tmp, target_path)
  if not renamed then
    pcall(uv.fs_unlink, tmp)
    error("atomic_write_file: fs_rename failed for " .. tmp .. " -> " .. target_path .. ": " .. tostring(rename_err))
  end

  return true
end

--- Atomically commit a SET of files as close to together as POSIX allows.
---
--- Every temp is written and fsynced FIRST, and only then are the renames
--- issued back to back. This is what the rolling seal needs: its
--- `manifest-<id>.json` and `manifest-<id>.sig` are rewritten repeatedly into a
--- directory that is under git and gets committed, and a `.json` committed
--- beside a stale `.sig` is a signed artifact that does not verify.
---
--- POSIX cannot rename two files as one operation, so a reader that looks
--- between the two renames still sees a new `.json` beside the previous `.sig`.
--- Staging first shrinks that window to a single syscall, which is the best
--- available without a journal. It is reported, not silently survived: a
--- `git commit` landing inside that window produces a signature failure naming
--- the session, which is the correct outcome for evidence we cannot vouch for.
---
--- If staging fails for any entry, NOTHING is renamed and every temp already
--- written is cleaned up — the previous pair on disk is left intact and
--- self-consistent. If a rename fails part-way, the remaining temps are cleaned
--- up and the error is raised.
---
--- @param entries table  list of { target_path = string, contents = string }
--- @return boolean true on success
function M.atomic_write_file_pair(entries)
  local uv = vim.uv or vim.loop

  local staged = {}
  local stage_ok, stage_err = pcall(function()
    for _, entry in ipairs(entries) do
      staged[#staged + 1] = {
        tmp = stage(uv, entry.target_path, entry.contents),
        target_path = entry.target_path,
      }
    end
  end)
  if not stage_ok then
    for _, s in ipairs(staged) do
      pcall(uv.fs_unlink, s.tmp)
    end
    error(stage_err)
  end

  for i, s in ipairs(staged) do
    local renamed, rename_err = uv.fs_rename(s.tmp, s.target_path)
    if not renamed then
      -- Clean up the temps that have not been committed yet, including this
      -- one. Already-renamed targets stay: undoing them would need the bytes
      -- they replaced, which are gone.
      for j = i, #staged do
        pcall(uv.fs_unlink, staged[j].tmp)
      end
      error(
        "atomic_write_file_pair: fs_rename failed for "
          .. s.tmp
          .. " -> "
          .. s.target_path
          .. ": "
          .. tostring(rename_err)
      )
    end
  end

  return true
end

--- Write `contents` to a fresh sibling temp file of `target_path` and fsync it,
--- WITHOUT renaming. Returns the temp path, which the caller must either rename
--- over the target or unlink. Raises on any I/O failure, cleaning up its own
--- temp file first.
---
--- Split out of atomic_write_file so a SET of files can be fully staged before
--- any of them is committed — see atomic_write_file_pair.
--- @param uv table
--- @param target_path string
--- @param contents string
--- @return string tmp path
stage = function(uv, target_path, contents)
  local pid = (uv.os_getpid and uv.os_getpid()) or vim.fn.getpid()
  local tmp = target_path .. "." .. tostring(pid) .. "." .. random_hex(uv) .. ".tmp"

  local fd = nil

  local function fail(msg)
    if fd ~= nil then
      pcall(uv.fs_close, fd)
      fd = nil
    end
    pcall(uv.fs_unlink, tmp)
    error(msg)
  end

  local open_fd, open_err = uv.fs_open(tmp, "w", 420) -- 420 = 0o644
  if not open_fd then
    fail("atomic_write_file: fs_open failed for " .. tmp .. ": " .. tostring(open_err))
  end
  fd = open_fd

  local written, write_err = uv.fs_write(fd, contents)
  if type(written) ~= "number" then
    fail("atomic_write_file: fs_write failed for " .. tmp .. ": " .. tostring(write_err))
  end

  local synced, sync_err = uv.fs_fsync(fd)
  if not synced then
    fail("atomic_write_file: fs_fsync failed for " .. tmp .. ": " .. tostring(sync_err))
  end

  local closed, close_err = uv.fs_close(fd)
  if not closed then
    -- fd may or may not still be valid after a failed close; don't try to
    -- close it again, just clean up the temp path and re-raise.
    fd = nil
    pcall(uv.fs_unlink, tmp)
    error("atomic_write_file: fs_close failed for " .. tmp .. ": " .. tostring(close_err))
  end
  fd = nil

  return tmp
end

return M
