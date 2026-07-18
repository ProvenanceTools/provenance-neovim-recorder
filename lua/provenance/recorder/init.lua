--- Activation bootstrap (design.md §5, task 6): the plugin entry point that
--- wires activation.load_and_verify + state + status together behind
--- VimEnter/DirChanged autocmds. This is the FINAL wiring task of Plan 3 —
--- it records nothing yet (recording is Plan 4). On an active workspace it
--- populates the module-level RecorderState and attaches the status
--- segment; on an inactive workspace it registers an inert :ProvenanceSeal
--- stub that only shows guidance and never records.
local state_mod = require("provenance.recorder.state")
local status = require("provenance.recorder.status")

local M = {}

local AUGROUP_NAME = "Provenance"
local SEAL_COMMAND_NAME = "ProvenanceSeal"

--- setup(opts?)
--- @param opts table|nil
---   workspace: string|nil        -- workspace root override (else vim.fn.getcwd())
---   load_and_verify: function|nil -- injectable loader seam for tests;
---     defaults to provenance.recorder.activation.load_and_verify
--- @return table handle with dispose()
function M.setup(opts)
  opts = opts or {}

  local load_and_verify = opts.load_and_verify
    or require("provenance.recorder.activation").load_and_verify

  -- Module-level RecorderState: single-workspace, one Neovim session.
  local state = state_mod.new()

  -- Factored so both the immediate setup() call and the later
  -- VimEnter/DirChanged autocmds drive the exact same resolve+load+apply
  -- path (task brief requirement).
  local function resolve_and_apply()
    local workspace = opts.workspace or vim.fn.getcwd()
    local result = load_and_verify(workspace)

    if result.status == "active" then
      state.activate({ workspace = workspace, manifest = result.manifest })
      status.attach(state)
    else
      -- Debug-level only: an unactivated cwd (e.g. the student's home
      -- directory, an unrelated project) is the common case, not something
      -- to surface to the user every time they open Neovim.
      vim.notify(
        string.format("Provenance: workspace not activated (%s)", tostring(result.reason)),
        vim.log.levels.DEBUG
      )
      state.deactivate()

      if vim.fn.exists(":" .. SEAL_COMMAND_NAME) == 0 then
        vim.api.nvim_create_user_command(SEAL_COMMAND_NAME, function()
          vim.notify(
            "Provenance: not an activated assignment workspace; nothing to seal.",
            vim.log.levels.INFO
          )
        end, {
          desc = "Provenance: seal the recorded submission bundle (inactive stub)",
        })
      end
    end
  end

  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })

  vim.api.nvim_create_autocmd({ "VimEnter", "DirChanged" }, {
    group = augroup,
    callback = resolve_and_apply,
    desc = "Provenance: re-evaluate activation on workspace entry/change",
  })

  -- Run once immediately so tests (and a setup() call after VimEnter has
  -- already fired) see the resolved state without waiting for the next
  -- autocmd event.
  resolve_and_apply()

  local handle = {}

  --- Tear down everything setup() registered: the augroup (and its
  --- autocmds), the attached status, and the inert seal command if one was
  --- created. Idempotent-ish: safe to call once per handle.
  function handle.dispose()
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
    status.detach()
    pcall(vim.api.nvim_del_user_command, SEAL_COMMAND_NAME)
  end

  return handle
end

return M
