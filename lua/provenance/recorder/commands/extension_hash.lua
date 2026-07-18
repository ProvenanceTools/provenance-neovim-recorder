--- Real extension_hash: a deterministic sha256 DirectoryHash over a source
--- tree, used for `session.start.recorder` / the bundle manifest's
--- `extension_hash` field and checked against the analyzer's
--- `known-good-extension-hashes.json` allowlist (design.md §8, §6).
---
--- Port of the monorepo's `packages/recorder/src/commands/extension-hash.ts`
--- (`computeExtensionHash`), with ONE deliberate deviation from that
--- reference: the sort order.
---
--- SORT ORDER — codepoint sort, NOT localeCompare (a design decision, not a
--- shortcut):
---   The TS reference sorts relative paths with `String.prototype.localeCompare`,
---   which is LOCALE-DEPENDENT — it can produce a different order on a
---   different machine or ICU version, which would make the hash
---   non-reproducible across environments. That is fine for the TS tool
---   (it's a one-off, run once per machine to compute a hash to compare
---   against a pinned value) but wrong as a *contract* for this Lua port,
---   where BOTH the sealed bundle's extension_hash and the monorepo
---   allowlist entry are produced by running THIS module's compute_installed()
---   — so they only need to agree with each other, not with localeCompare.
---   We sort with plain `table.sort(rel_paths)`, which compares Lua strings
---   byte-by-byte. For UTF-8 encoded text, byte order == Unicode codepoint
---   order (a structural property of UTF-8: continuation bytes are always
---   numerically greater within a multi-byte sequence, and later codepoints
---   always start with a numerically greater leading byte). So plain
---   `table.sort` on relative paths IS a codepoint sort, and it is fully
---   deterministic: same tree → same order, on any machine, regardless of
---   locale/ICU. Do not "fix" this to emulate localeCompare.
---
--- Algorithm (matches extension-hash.ts otherwise):
---   1. Recursively walk root_dir, collecting regular files only. Skip
---      symlinks and any other non-regular entry. An unreadable/missing
---      root_dir is treated as an empty tree (not an error).
---   2. Map each file to its path relative to root_dir, forward-slash
---      separated.
---   3. Sort relative paths (table.sort — see note above).
---   4. Roll: for each file in sorted order, concatenate
---        <relpath bytes> .. "\0" .. <file raw bytes>
---      into one byte string.
---   5. sha256 the result; return 64-char lowercase hex.
---
--- Empty tree → sha256("") == the pinned
---   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
---
--- Pure I/O over vim.uv; no other Neovim editor API.
local core_sha256 = require("provenance.core.sha256")

local M = {}

-- ---------------------------------------------------------------------------
-- Internal helpers
-- ---------------------------------------------------------------------------

--- Read a whole file's raw bytes via vim.uv. Never throws.
--- @param path string
--- @return string|nil  file bytes, or nil if the file can't be read
local function read_file_bytes(path)
  local uv = vim.uv or vim.loop
  local fd = uv.fs_open(path, "r", 438) -- 438 = 0o666
  if not fd then
    return nil
  end
  local ok, data = pcall(function()
    local st = uv.fs_fstat(fd)
    if not st then
      error("fstat failed")
    end
    local chunk = uv.fs_read(fd, st.size, 0)
    if chunk == nil then
      error("read failed")
    end
    return chunk
  end)
  uv.fs_close(fd) -- always close, on both the success and error paths
  if not ok then
    return nil
  end
  return data
end

--- Recursively walk `dir`, collecting absolute paths of regular files only.
--- Directories are recursed into (not collected as entries). Symlinks and
--- any other non-regular type are skipped. An unreadable/missing directory
--- contributes nothing (never throws).
--- @param dir string
--- @param out table  accumulator of absolute file paths
local function walk(dir, out)
  local uv = vim.uv or vim.loop
  local handle = uv.fs_scandir(dir)
  if not handle then
    return
  end
  while true do
    local name, ftype = uv.fs_scandir_next(handle)
    if name == nil then
      break
    end
    local full = dir .. "/" .. name

    -- fs_scandir_next's ftype is usually available and cheap; fall back to
    -- fs_lstat (NOT fs_stat, which follows symlinks) when it's absent so
    -- symlinks are still reliably skipped rather than silently followed.
    if ftype == nil then
      local lst = uv.fs_lstat(full)
      ftype = lst and lst.type or nil
    end

    if ftype == "directory" then
      walk(full, out)
    elseif ftype == "file" then
      out[#out + 1] = full
    end
    -- "link" (symlink) and any other type: intentionally skipped.
  end
end

--- Normalize a path separator to forward-slash (defensive; vim.uv paths on
--- the supported platforms already use "/", but this guards against a
--- stray backslash creeping in).
--- @param p string
--- @return string
local function to_forward_slashes(p)
  return (p:gsub("\\", "/"))
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

--- Compute the DirectoryHash of `root_dir`: a reproducible sha256 over every
--- regular file's relative path and contents, in codepoint-sorted order.
--- @param root_dir string  absolute path to the directory to hash
--- @return string  64-char lowercase hex sha256 digest
function M.compute(root_dir)
  local abs_paths = {}
  walk(root_dir, abs_paths)

  -- root_dir with a single trailing slash stripped, so relative-path
  -- computation below doesn't produce a leading "/".
  local root_prefix = root_dir:gsub("/+$", "") .. "/"

  local rel_paths = {}
  local rel_to_abs = {}
  for _, abs in ipairs(abs_paths) do
    local rel = abs
    if abs:sub(1, #root_prefix) == root_prefix then
      rel = abs:sub(#root_prefix + 1)
    end
    rel = to_forward_slashes(rel)
    rel_paths[#rel_paths + 1] = rel
    rel_to_abs[rel] = abs
  end

  -- Codepoint sort: table.sort on UTF-8 byte strings IS a codepoint sort.
  -- See the module-level comment for why this replaces localeCompare.
  table.sort(rel_paths)

  local parts = {}
  for _, rel in ipairs(rel_paths) do
    local abs = rel_to_abs[rel]
    local bytes = read_file_bytes(abs)
    if bytes == nil then
      error("extension_hash.compute: failed to read file: " .. abs)
    end
    parts[#parts + 1] = rel
    parts[#parts + 1] = "\0"
    parts[#parts + 1] = bytes
  end

  return core_sha256.hex(table.concat(parts))
end

--- Resolve this plugin's own `lua/` directory and hash it. This is the real
--- extension_hash used by seal.lua by default: the tree-hash of the
--- installed plugin's Lua source, stable regardless of install location
--- (relative paths are relative to `lua/`, e.g. "provenance/core/sha256.lua").
--- @return string  64-char lowercase hex sha256 digest
function M.compute_installed()
  local ok, lua_dir = pcall(function()
    -- This file lives at <...>/lua/provenance/recorder/commands/extension_hash.lua.
    -- debug.getinfo(1, "S").source is "@<absolute path to this file>".
    local info = debug.getinfo(1, "S")
    local source = info.source
    if type(source) ~= "string" or source:sub(1, 1) ~= "@" then
      error("could not resolve source path for extension_hash.lua")
    end
    local this_file = source:sub(2)

    -- Walk up 4 directories: commands/ -> recorder/ -> provenance/ -> lua/.
    local dir = this_file
    for _ = 1, 4 do
      dir = dir:match("^(.*)/[^/]+$")
      if dir == nil then
        error("could not walk up to lua/ from " .. this_file)
      end
    end
    return dir
  end)

  if not ok then
    error("extension_hash.compute_installed: " .. tostring(lua_dir))
  end

  return M.compute(lua_dir)
end

return M
