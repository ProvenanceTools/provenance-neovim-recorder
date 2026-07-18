--- Plugin snapshot wiring (Plan 7 / Task 4): an always-on `ext.snapshot`
--- listing the loaded Neovim plugins, emitted immediately at session start
--- and again every `interval_ms` (default 5 minutes) thereafter.
---
--- Composes the pure `snapshot_payloads.build_ext_snapshot` builder (Task 3)
--- with a `vim.uv` timer; mirrors heartbeat.lua's testability idiom —
--- `handle._tick()` is exposed so tests can drive re-emits deterministically
--- instead of relying on real wall-clock timer firing (CLAUDE.md:
--- "Determinism. Inject clocks... no real timing in assertions").
local snapshot_payloads = require("provenance.recorder.events.snapshot_payloads")

local M = {}

local DEFAULT_INTERVAL_MS = 300000 -- 5 minutes

--- Best-effort default plugin enumeration: every entry on the runtimepath,
--- deduped by basename-as-id. Most Neovim plugins expose no queryable
--- version, so version is always "" here; being on the runtimepath is taken
--- to mean active, so enabled is always true. Exact plugin-manager
--- integration (querying a manager's own plugin list/version) is out of
--- scope — this is a coarse, degraded-by-design signal, wrapped in pcall by
--- the caller so a failure here degrades to an empty list rather than
--- crashing the snapshot.
local function default_list_plugins()
  local plugins = {}
  local seen = {}
  for _, path in ipairs(vim.api.nvim_list_runtime_paths()) do
    local id = vim.fs.basename(path)
    if id and id ~= "" and not seen[id] then
      seen[id] = true
      table.insert(plugins, { id = id, version = "", enabled = true })
    end
  end
  return plugins
end

--- list_plugins() -> list of {id, version, enabled}
---
--- Wraps default_list_plugins in pcall so any failure enumerating the
--- runtimepath (missing API, unexpected environment) degrades to an empty
--- list — a missing/broken plugin-manager integration is a degraded signal,
--- never a crash (CLAUDE.md).
local function safe_default_list_plugins()
  local ok, result = pcall(default_list_plugins)
  if not ok then
    return {}
  end
  return result
end

--- start(opts) -> handle
--- @param opts table {
---   emit: function(kind, data)             -- SessionHost.emit
---   list_plugins?: function() -> list of {id, version, enabled}
---   interval_ms?: number (default 300000)
---   get_now?: function() -> number (ms)     -- unused today; accepted for
---                                               interface parity/future use
--- }
--- @return table handle { dispose(), _tick() }
function M.start(opts)
  opts = opts or {}

  local emit = opts.emit
  local list_plugins = opts.list_plugins or safe_default_list_plugins
  local interval_ms = opts.interval_ms or DEFAULT_INTERVAL_MS

  local disposed = false

  local handle = {}

  --- Build the payload and emit one `ext.snapshot`. Exposed as
  --- `handle._tick()` so tests can drive re-emits deterministically.
  function handle._tick()
    if disposed then
      return
    end

    local plugins = list_plugins()
    local ev = snapshot_payloads.build_ext_snapshot(plugins)
    emit(ev.kind, ev.data)
  end

  -- Immediate emit at session start.
  handle._tick()

  local uv = vim.uv or vim.loop
  local timer = uv.new_timer()
  timer:start(interval_ms, interval_ms, vim.schedule_wrap(function()
    if disposed then
      return
    end
    pcall(handle._tick)
  end))
  -- A pending snapshot must never keep Neovim from exiting.
  timer:unref()

  --- Idempotent teardown: stop + close the timer, mark disposed so no
  --- further ticks (manual or timer-driven) emit.
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
