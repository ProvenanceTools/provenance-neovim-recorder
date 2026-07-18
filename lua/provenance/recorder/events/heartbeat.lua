--- Heartbeat: a periodic `session.heartbeat` event carrying focus state,
--- the active file, and idle duration (recorder PRD §5.1). This is a
--- background timer, not a hot-path emitter — it fires once every
--- `interval_ms`, never on a keystroke.
---
--- Every value the tick needs (`get_now`, `get_focused`, `get_active_file`,
--- `emit`) is injected, so the payload-building logic is testable as a pure
--- function via the exposed `handle._tick()`, separately from the real
--- `vim.uv` timer (mirrors CLAUDE.md's "test the event-to-log-entry
--- transform as a pure function, separately from the editor wiring").
local core_json = require("provenance.core.json")

local M = {}

local DEFAULT_INTERVAL_MS = 30000

local function default_get_now()
  return (vim.uv or vim.loop).hrtime() / 1e6
end

local function default_get_focused()
  return true
end

--- Simple production default: the current buffer's full path, or nil if it
--- has none. Callers that want a workspace-relative path (e.g.
--- recording_session composing this against an activated workspace) inject
--- their own `get_active_file`.
local function default_get_active_file()
  local ok, name = pcall(vim.api.nvim_buf_get_name, 0)
  if not ok or name == "" then
    return nil
  end
  return name
end

--- start(opts) -> handle
--- @param opts table {
---   interval_ms?: number (default 30000),
---   emit: function(kind, data)         -- SessionHost.emit
---   get_now?: function() -> number (ms)
---   get_focused?: function() -> boolean
---   get_active_file?: function() -> string|nil
--- }
--- @return table handle { mark_activity(), dispose(), _tick() }
function M.start(opts)
  opts = opts or {}

  local interval_ms = opts.interval_ms or DEFAULT_INTERVAL_MS
  local emit = opts.emit
  local get_now = opts.get_now or default_get_now
  local get_focused = opts.get_focused or default_get_focused
  local get_active_file = opts.get_active_file or default_get_active_file

  local disposed = false
  local last_activity_ms = get_now()

  local handle = {}

  --- Build the payload and emit one `session.heartbeat`. Exposed as
  --- `handle._tick()` so tests can drive ticks deterministically without
  --- relying on real wall-clock timer firing.
  function handle._tick()
    if disposed then
      return
    end

    local now = get_now()
    local active_file = get_active_file()
    if active_file == nil then
      active_file = core_json.NULL
    end

    emit("session.heartbeat", {
      focused = get_focused(),
      active_file = active_file,
      idle_since_ms = math.max(0, now - last_activity_ms),
    })
  end

  --- Reset the idle clock. Callers invoke this on focus/buffer-change
  --- signals so `idle_since_ms` reflects genuine inactivity, not merely the
  --- time since the last heartbeat tick.
  function handle.mark_activity()
    last_activity_ms = get_now()
  end

  local uv = vim.uv or vim.loop
  local timer = uv.new_timer()
  timer:start(interval_ms, interval_ms, vim.schedule_wrap(function()
    if disposed then
      return
    end
    pcall(handle._tick)
  end))
  -- A pending heartbeat must never keep Neovim from exiting.
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
