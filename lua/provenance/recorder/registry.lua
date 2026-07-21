--- registry.lua — the root -> session map (Plan:
--- 2026-07-20-nested-manifest-discovery). Replaces the single module-level
--- `state`/`controller` pair recorder/init.lua used to own with a table
--- keyed by assignment root, so more than one assignment can record at the
--- same instant, each with its own live recording_controller session.
---
--- Deliberately dumb: this module does not know about discovery, buffers,
--- or autocmds -- it only tracks "which roots currently have a live
--- session" and starts/stops sessions via an injected start_recording seam
--- (production: recording_controller.start; tests: a spy, mirroring
--- init_controller_spec.lua's existing style).
local M = {}

--- @param opts table { start_recording: function(start_opts) -> controller }
--- @return table registry
function M.new(opts)
  opts = opts or {}
  local start_recording = opts.start_recording

  -- root -> { manifest, controller, provenance_dir }
  local sessions = {}

  local reg = {}

  --- Aggregate, no-arg (deliberately named to match RecorderState.is_active()
  --- so status.attach(reg) works unmodified): true iff at least one session
  --- is currently registered.
  function reg.is_active()
    return next(sessions) ~= nil
  end

  --- @param root string
  --- @return boolean
  function reg.has_session(root)
    return sessions[root] ~= nil
  end

  --- @param root string
  --- @return table|nil { manifest, controller, provenance_dir }
  function reg.get(root)
    return sessions[root]
  end

  --- @return table[]  { root, manifest, controller }, sorted by root ascending
  function reg.list()
    local out = {}
    for root, entry in pairs(sessions) do
      out[#out + 1] = { root = root, manifest = entry.manifest, controller = entry.controller }
    end
    table.sort(out, function(a, b)
      return a.root < b.root
    end)
    return out
  end

  --- Idempotent: if `root` already has a live session, returns it unchanged
  --- (does not call start_recording again). Otherwise starts one.
  --- @param root string
  --- @param manifest table
  --- @param extra_opts table|nil  merged into the start_recording opts,
  ---   winning on any key collision with the derived workspace/provenance_dir/manifest
  --- @return table|nil controller, boolean started, string|nil err
  function reg.ensure_session(root, manifest, extra_opts)
    local existing = sessions[root]
    if existing then
      return existing.controller, false
    end

    local provenance_dir = root .. "/.provenance"
    local start_opts = vim.tbl_extend("force", {
      workspace = root,
      provenance_dir = provenance_dir,
      manifest = manifest,
    }, extra_opts or {})

    local ok, controller = pcall(start_recording, start_opts)
    if not ok then
      return nil, false, controller
    end

    sessions[root] = { manifest = manifest, controller = controller, provenance_dir = provenance_dir }
    return controller, true
  end

  --- Stop every registered session (pcall-guarded per entry, so one
  --- failing stop() never blocks the others) and clear the registry.
  --- Order-independent by construction (Lua's pairs() order is
  --- unspecified) -- this is deliberate: see paste_intercept.lua's
  --- ref-counted-singleton fix for why teardown order must never matter.
  --- @param reason string|nil
  function reg.stop_all(reason)
    for root, entry in pairs(sessions) do
      pcall(entry.controller.stop, reason)
      sessions[root] = nil
    end
  end

  return reg
end

return M
