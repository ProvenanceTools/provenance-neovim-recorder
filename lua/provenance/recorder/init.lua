--- Activation bootstrap (design.md §5): the plugin entry point that wires
--- activation.load_and_verify + state + status together behind
--- VimEnter/DirChanged autocmds. On an active workspace it populates the
--- module-level RecorderState, attaches the status segment, and (Plan 9)
--- starts the full-signals recording_controller for that workspace — stopping
--- it on deactivation/dispose. On an inactive workspace it registers an inert
--- :ProvenanceSeal stub that only shows guidance and never records.
local state_mod = require("provenance.recorder.state")
local status = require("provenance.recorder.status")
local recording_controller = require("provenance.recorder.session.recording_controller")
local core_clock = require("provenance.core.clock")

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

  -- The full-signals recording session started on a real activation (Plan 9).
  -- Injectable seam: opts.start_recording defaults to the real controller.
  local start_recording = opts.start_recording or recording_controller.start

  -- Only start a REAL recording session on a REAL activation. init_spec injects
  -- a fake load_and_verify and asserts state/status/augroup WITHOUT starting a
  -- live session (its fake manifest has no sig/files_under_review and its
  -- workspace is a throwaway path). Gate the start: skip when the loader was
  -- injected, UNLESS a fake start_recording was ALSO injected (the seam a
  -- controller-wiring test would use to observe the start without a real one).
  local should_start_recording = (opts.load_and_verify == nil) or (opts.start_recording ~= nil)

  -- Lifecycle: at most one live controller, keyed by the workspace it records.
  local controller = nil
  local controller_workspace = nil

  local function stop_controller()
    if controller then
      pcall(controller.stop, "deactivate")
      controller = nil
      controller_workspace = nil
    end
  end

  -- Factored so both the immediate setup() call and the later
  -- VimEnter/DirChanged autocmds drive the exact same resolve+load+apply
  -- path (task brief requirement).
  local function resolve_and_apply()
    local workspace = opts.workspace or vim.fn.getcwd()
    local result = load_and_verify(workspace)

    if result.status == "active" then
      state.activate({ workspace = workspace, manifest = result.manifest })
      status.attach(state)

      -- Start the live recording controller for this workspace (Plan 9). The
      -- controller-workspace guard makes this idempotent: a re-fire of
      -- resolve_and_apply for the SAME already-recording workspace (e.g. the
      -- immediate call plus a VimEnter) leaves the existing session running
      -- rather than leaking it and starting a second one. A genuine workspace
      -- change stops the old session first. pcall-guarded so a start failure
      -- degrades gracefully rather than breaking Neovim startup.
      if should_start_recording and controller_workspace ~= workspace then
        stop_controller()
        local ok, c = pcall(start_recording, {
          workspace = workspace,
          provenance_dir = workspace .. "/.provenance",
          manifest = result.manifest,
          clock = core_clock.system(),
        })
        if ok then
          controller = c
          controller_workspace = workspace
        elseif vim.g.provenance_debug then
          vim.notify(
            "Provenance: failed to start recording: " .. tostring(c),
            vim.log.levels.ERROR
          )
        end
      end

      -- Register the LIVE :ProvenanceSeal command for this active workspace.
      -- nvim_create_user_command overwrites any prior definition by default,
      -- so this replaces the inert stub the INACTIVE branch may have left
      -- behind. The callback closes over the `controller` upvalue (not a
      -- snapshot) so a later workspace change — which stops the old
      -- controller and starts a new one via the guard above — still seals
      -- whatever session is current when :ProvenanceSeal actually runs.
      vim.api.nvim_create_user_command(SEAL_COMMAND_NAME, function()
        if not controller then
          vim.notify("Provenance: no active recording session to seal.", vim.log.levels.INFO)
          return
        end
        local ok, result = pcall(controller.seal)
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
        else -- write_error (or any other)
          vim.notify(
            "Provenance: seal failed: " .. tostring(result.message or result.kind),
            vim.log.levels.ERROR
          )
        end
      end, { desc = "Provenance: seal the recorded submission bundle" })
    else
      -- Leaving/entering an unactivated workspace stops any live session.
      stop_controller()
      -- Silent by default: an unactivated cwd (e.g. the student's home
      -- directory, an unrelated project) is the common case, not something
      -- to surface to the user every time they open Neovim or `cd`s.
      -- vim.notify does NOT filter by level on its own (even DEBUG is
      -- echoed unconditionally by the default handler), so gate this
      -- explicitly behind an opt-in debug flag rather than relying on the
      -- level argument to suppress it.
      if vim.g.provenance_debug then
        vim.notify(
          string.format("Provenance: workspace not activated (%s)", tostring(result.reason)),
          vim.log.levels.DEBUG
        )
      end
      state.deactivate()

      -- Register the INERT :ProvenanceSeal stub unconditionally.
      -- nvim_create_user_command overwrites any prior definition by default,
      -- so this always replaces a stale LIVE command (registered by the
      -- ACTIVE branch above) with the inert stub. Without this, a prior
      -- vim.fn.exists guard here meant that once the live command had ever
      -- been registered, this branch would skip re-registering the stub —
      -- leaving the stale live callback (closing over a now-nil controller)
      -- bound after deactivation, producing the wrong "no active recording
      -- session to seal" message instead of the inactive-workspace guidance.
      -- Repeated inactive re-fires just re-register the same stub, which is
      -- harmless (idempotent).
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
    stop_controller()
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
    status.detach()
    pcall(vim.api.nvim_del_user_command, SEAL_COMMAND_NAME)
  end

  return handle
end

return M
