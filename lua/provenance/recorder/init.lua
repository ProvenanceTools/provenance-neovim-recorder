--- Activation bootstrap (design.md §5; plan 2026-07-20-nested-manifest-discovery):
--- the plugin entry point that wires discovery + registry + status together
--- behind autocmds. Upward, file-anchored manifest discovery replaces the old
--- cwd-anchored single-workspace model: opening a file (BufEnter/BufReadPost/
--- BufNewFile) walks upward to that file's nearest ancestor manifest and, on a
--- verified match, ensures a live recording_controller session for that root in
--- the registry -- so more than one assignment can record concurrently in one
--- Neovim process. The cwd (VimEnter/DirChanged) remains a fallback anchor for
--- buffers with no file path. :ProvenanceSeal is registered once and queries
--- the registry live at invocation time.
local status = require("provenance.recorder.status")
local recording_controller = require("provenance.recorder.session.recording_controller")
local core_clock = require("provenance.core.clock")
local discovery = require("provenance.recorder.discovery")
local registry_mod = require("provenance.recorder.registry")

local M = {}

local AUGROUP_NAME = "Provenance"
local SEAL_COMMAND_NAME = "ProvenanceSeal"

--- setup(opts?)
--- @param opts table|nil
---   workspace: string|nil        -- cwd override for the VimEnter/DirChanged
---     fallback anchor (a buffer with no file path); production default is
---     vim.fn.getcwd()
---   resolve: function|nil        -- (start_dir) -> {status, root?, manifest?, reason?};
---     injectable seam for tests; defaults to discovery.resolve_from_dir
---   start_recording: function|nil -- (start_opts) -> controller; injectable
---     seam for tests; defaults to recording_controller.start
--- @return table handle with dispose()
function M.setup(opts)
  opts = opts or {}

  local resolve = opts.resolve or discovery.resolve_from_dir
  local start_recording = opts.start_recording or recording_controller.start

  local registry = registry_mod.new({ start_recording = start_recording })
  status.attach(registry)

  --- Resolve a single anchor directory and, if active, ensure its session
  --- exists in the registry. Idempotent (registry.ensure_session already
  --- guards against double-starting the same root).
  local function resolve_and_activate(start_dir)
    local result = resolve(start_dir)
    if result.status == "active" then
      registry.ensure_session(result.root, result.manifest, { clock = core_clock.system() })
    end
    return result
  end

  --- The cwd-anchor path (VimEnter/DirChanged): fires rarely (only on a real
  --- :cd or Neovim startup), so it keeps the pre-existing debug notification
  --- on an inactive resolve -- exactly the old single-workspace behavior,
  --- byte-for-byte. Deliberately NOT added to resolve_buf (Phase B):
  --- BufEnter/BufReadPost/BufNewFile fire on every buffer open, so the same
  --- notification there would spam vim.g.provenance_debug users on every
  --- non-assignment file they open (a scratch buffer, their own dotfiles,
  --- etc.) -- a real behavioral difference from the old cwd-only design
  --- this task deliberately does not carry forward into the new per-buffer
  --- trigger.
  local function resolve_cwd()
    local result = resolve_and_activate(opts.workspace or vim.fn.getcwd())
    if result.status ~= "active" and vim.g.provenance_debug then
      vim.notify(
        string.format("Provenance: workspace not activated (%s)", tostring(result.reason)),
        vim.log.levels.DEBUG
      )
    end
  end

  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })

  vim.api.nvim_create_autocmd({ "VimEnter", "DirChanged" }, {
    group = augroup,
    callback = resolve_cwd,
    desc = "Provenance: re-evaluate activation on cwd change (fallback anchor for buffers with no file path)",
  })

  vim.api.nvim_create_autocmd("VimLeavePre", {
    group = augroup,
    callback = function()
      registry.stop_all("deactivate")
    end,
    desc = "Provenance: end every live recording session before Neovim exits",
  })

  --- :ProvenanceSeal -- registered ONCE, unconditionally. Its body queries
  --- the registry LIVE at invocation time, so there is no more "live vs
  --- inert stub command" swap to keep in sync (that swap was the source of
  --- a real bug fixed earlier in this file's history -- see git blame on
  --- init_seal_command_spec.lua's round-trip regression test). Phase C adds
  --- the multi-session picker; this phase preserves single-session behavior
  --- exactly.
  vim.api.nvim_create_user_command(SEAL_COMMAND_NAME, function()
    local active = registry.list()
    if #active == 0 then
      vim.notify("Provenance: not an activated assignment workspace; nothing to seal.", vim.log.levels.INFO)
      return
    end

    local entry = active[1]
    local ok, result = pcall(entry.controller.seal)
    if not ok then
      vim.notify("Provenance: seal failed: " .. tostring(result), vim.log.levels.ERROR)
      return
    end
    if result.kind == "ok" then
      if result.warnings and result.warnings.chain_broken then
        vim.notify(
          "Provenance: sealed WITH WARNINGS (hash chain broken) -> " .. result.bundle_path,
          vim.log.levels.WARN
        )
      else
        vim.notify("Provenance: sealed submission bundle -> " .. result.bundle_path, vim.log.levels.INFO)
      end
    elseif result.kind == "no_sessions" then
      vim.notify("Provenance: nothing to seal (no recorded sessions).", vim.log.levels.WARN)
    else
      vim.notify("Provenance: seal failed: " .. tostring(result.message or result.kind), vim.log.levels.ERROR)
    end
  end, { desc = "Provenance: seal the recorded submission bundle" })

  -- Run once immediately so tests (and a setup() call after VimEnter has
  -- already fired) see the resolved state without waiting for the next
  -- autocmd event.
  resolve_cwd()

  local handle = {}

  function handle.dispose()
    registry.stop_all("deactivate")
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
    status.detach()
    pcall(vim.api.nvim_del_user_command, SEAL_COMMAND_NAME)
  end

  return handle
end

return M
