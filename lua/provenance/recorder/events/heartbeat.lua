--- Heartbeat: a periodic `session.heartbeat` event carrying focus state,
--- the active file, and idle duration (recorder PRD §5.1). This is a
--- background timer, not a hot-path emitter — it fires once every
--- `interval_ms`, never on a keystroke.
---
--- Suspend detection: a libuv timer never fires while the OS has the process
--- suspended (laptop lid closed), so a tick can land far later than
--- `interval_ms` after the previous one. When wall-clock time between ticks
--- is at least 2x the expected interval, a `session.resumed {gap_ms,
--- expected_interval_ms}` marker is emitted immediately before that tick's
--- `session.heartbeat`, so the marker's seq lands strictly between the two
--- bounding heartbeat seqs (the analyzer suppresses `gap_in_heartbeats` over
--- a seq range that contains one). This deliberately uses wall-clock time
--- (`get_wall_ms`), not the monotonic clock used for `idle_since_ms`: monotonic
--- clocks are not a reliable suspend signal across platforms (behavior
--- differs between macOS and Linux), whereas comparing wall-clock elapsed
--- time to the expected tick interval works everywhere.
---
--- Every value the tick needs (`get_now`, `get_wall_ms`, `get_focused`,
--- `get_active_file`, `emit`) is injected, so the payload-building logic is
--- testable as a pure function via the exposed `handle._tick()`, separately
--- from the real `vim.uv` timer (mirrors CLAUDE.md's "test the
--- event-to-log-entry transform as a pure function, separately from the
--- editor wiring").
local core_json = require("provenance.core.json")

local M = {}

local DEFAULT_INTERVAL_MS = 30000

local function default_get_now()
  return (vim.uv or vim.loop).hrtime() / 1e6
end

--- True wall clock (epoch ms), NOT vim.uv.now() (libuv's cached loop time)
--- and NOT hrtime() (monotonic). Mirrors clock_skew_watcher.lua's
--- default_get_wall_ms and log-core's `wall` field source.
local function default_get_wall_ms()
  local s, us = (vim.uv or vim.loop).gettimeofday()
  return s * 1000 + us / 1000
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
---   get_now?: function() -> number (ms)          -- monotonic, for idle_since_ms
---   get_wall_ms?: function() -> number (ms)       -- true wall clock, for suspend detection
---   get_focused?: function() -> boolean
---   get_active_file?: function() -> string|nil
--- }
--- @return table handle { mark_activity(), dispose(), _tick() }
function M.start(opts)
  opts = opts or {}

  local interval_ms = opts.interval_ms or DEFAULT_INTERVAL_MS
  local emit = opts.emit
  local get_now = opts.get_now or default_get_now
  local get_wall_ms = opts.get_wall_ms or default_get_wall_ms
  local get_focused = opts.get_focused or default_get_focused
  local get_active_file = opts.get_active_file or default_get_active_file

  local disposed = false
  local last_activity_ms = get_now()
  -- nil until the first tick completes: "a previous tick exists" (see the
  -- gap check below) is false for tick #1, so no session.resumed can fire
  -- before there is a prior tick to measure a gap against.
  local last_tick_wall_ms = nil

  local handle = {}

  --- Build the payload and emit one `session.heartbeat`, preceded by a
  --- `session.resumed` marker if wall-clock time since the previous tick was
  --- at least 2x the expected interval (the OS suspended the process, e.g.
  --- lid close, so the timer missed one or more ticks). Exposed as
  --- `handle._tick()` so tests can drive ticks deterministically without
  --- relying on real wall-clock timer firing.
  function handle._tick()
    if disposed then
      return
    end

    local now = get_now()
    local now_wall = get_wall_ms()

    if last_tick_wall_ms ~= nil then
      local gap_ms = now_wall - last_tick_wall_ms
      -- Negative gap = backwards NTP correction, not a suspend; never emit.
      if gap_ms >= 0 and gap_ms >= 2 * interval_ms then
        emit("session.resumed", { gap_ms = gap_ms, expected_interval_ms = interval_ms })
      end
    end
    last_tick_wall_ms = now_wall

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
