--- vim.uv deps layer for chain_recovery.recover_previous_session (Task 5).
--- chain_recovery.lua is pure logic over injected deps; this module is the
--- one place that seam is wired to the real Neovim runtime (`vim.uv`), same
--- allowed-primitive rule as the rest of `recorder/` (CLAUDE.md).
---
--- list_slogs returns ABSOLUTE paths (provenance_dir joined onto each name)
--- so that read_slog/rename — which chain_recovery calls with exactly what
--- list_slogs returned — operate on full paths without needing to know
--- provenance_dir themselves.
local core_clock = require("provenance.core.clock")

local M = {}

--- Read a whole file's raw bytes via vim.uv. Never throws. Binary-safe.
--- Mirrors commands/seal.lua's / watch/save_time_checker.lua's
--- read_file_bytes idiom.
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

--- @param provenance_dir string  absolute path to the session's .provenance dir
--- @return table deps  { list_slogs, read_slog, rename, now }
function M.new(provenance_dir)
  local deps = {}

  --- list_slogs() -> list of absolute paths of real `.slog` files in
  --- provenance_dir. Excludes `.slog.meta` sidecars (the anchored `%.slog$`
  --- pattern doesn't match a `.meta`-suffixed name) and quarantine files
  --- from a previous corrupt-recovery (`.corrupt-<ts>` doesn't end in
  --- `.slog` either, but is filtered explicitly for clarity, mirroring
  --- seal.lua's zip-entry skip list). Never throws: an unscannable dir
  --- yields an empty list.
  function deps.list_slogs()
    local uv = vim.uv or vim.loop
    local handle = uv.fs_scandir(provenance_dir)
    if not handle then
      return {}
    end
    local paths = {}
    while true do
      local name = uv.fs_scandir_next(handle)
      if name == nil then
        break
      end
      if name:match("%.slog$") and not name:find(".corrupt-", 1, true) then
        paths[#paths + 1] = provenance_dir .. "/" .. name
      end
    end
    return paths
  end

  --- read_slog(path) -> raw file text, or nil on read failure.
  function deps.read_slog(path)
    return read_file_bytes(path)
  end

  --- rename(from_path, to_path) -> ok, err. Best-effort: never throws.
  --- Mirrors atomic_write.lua's fs_rename usage: on success returns
  --- (true|renamed-value, nil); on failure returns (nil, err_message) — pcall
  --- guards against fs_rename itself raising, which luv's sync fs calls
  --- don't normally do, but chain_recovery's own quarantine() already wraps
  --- deps.rename in pcall too, so this is defense in depth.
  function deps.rename(from_path, to_path)
    local uv = vim.uv or vim.loop
    local pok, renamed, rename_err = pcall(uv.fs_rename, from_path, to_path)
    if not pok then
      return false, renamed
    end
    if not renamed then
      return false, rename_err
    end
    return true
  end

  --- now() -> fixed-width ISO wall-clock string safe to use inside a
  --- FILENAME (chain_recovery appends it after ".corrupt-"). The core wall
  --- formatter uses colons (HH:MM:SS); colons are invalid in filenames on
  --- some platforms, so they're replaced with dashes here.
  function deps.now()
    return (core_clock.system().wall()):gsub(":", "-")
  end

  return deps
end

return M
