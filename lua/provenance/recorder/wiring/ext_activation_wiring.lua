--- ext_activation_wiring.lua — emits `ext.activate` for plugins that become
--- loaded AFTER session start, mirroring VS Code's extension-activation poller
--- (packages/recorder/src/wiring/extension-activation.ts). Neovim, like VS
--- Code, exposes no public "plugin activated" event, so this polls the loaded-
--- plugin set on an interval and diffs it against what it has already seen.
---
--- Plugins present at session start are the BASELINE — they are already
--- covered by the immediate ext.snapshot and are NOT activations, so they are
--- recorded as seen without emitting. Only newly-appearing ids emit
--- ext.activate. Composes plugin_list (shared with snapshot_wiring) + a
--- `vim.uv` timer; `handle._tick()` is exposed so tests drive polls
--- deterministically (mirrors snapshot_wiring/heartbeat).
local snapshot_payloads = require("provenance.recorder.events.snapshot_payloads")
local plugin_list = require("provenance.recorder.wiring.plugin_list")

local M = {}

local DEFAULT_INTERVAL_MS = 300000 -- 5 minutes, same cadence as ext.snapshot

--- start(opts) -> handle
--- @param opts table {
---   emit: function(kind, data)              -- SessionHost.emit
---   list_plugins?: function() -> list of {id, version, enabled}
---   interval_ms?: number (default 300000)
--- }
--- @return table handle { dispose(), _tick() }
function M.start(opts)
  opts = opts or {}

  local emit = opts.emit
  local list_plugins = opts.list_plugins or plugin_list.list
  local interval_ms = opts.interval_ms or DEFAULT_INTERVAL_MS

  local disposed = false
  local seen = {}

  -- Baseline: everything already loaded at start is seen (no emit).
  for _, p in ipairs(list_plugins()) do
    if p.id then
      seen[p.id] = true
    end
  end

  local handle = {}

  --- Poll once: emit ext.activate for any not-yet-seen plugin. Exposed as
  --- handle._tick() for deterministic test-driven polls.
  function handle._tick()
    if disposed then
      return
    end
    for _, p in ipairs(list_plugins()) do
      if p.id and not seen[p.id] then
        seen[p.id] = true
        local ev = snapshot_payloads.build_ext_activate(p.id, p.version or "")
        emit(ev.kind, ev.data)
      end
    end
  end

  local uv = vim.uv or vim.loop
  local timer = uv.new_timer()
  timer:start(interval_ms, interval_ms, vim.schedule_wrap(function()
    if disposed then
      return
    end
    pcall(handle._tick)
  end))
  -- A pending activation poll must never keep Neovim from exiting.
  timer:unref()

  --- Idempotent teardown: stop + close the timer, mark disposed.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    pcall(function()
      timer:stop()
      timer:close()
    end)
  end

  return handle
end

return M
