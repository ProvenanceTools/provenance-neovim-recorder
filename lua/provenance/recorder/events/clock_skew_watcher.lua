--- Clock-skew watcher: a corroborating signal that emits `clock.skew
--- {delta_ms}` when the wall clock jumps non-monotonically relative to the
--- monotonic clock (PRD §4.2). Faithful port of clock-watcher.ts.
---
--- Behavior:
--- - Record t0_monotonic and t0_wall at start.
--- - On each tick: compute expected elapsed (monotonic delta) and actual
---   elapsed (wall delta).
--- - If |actual - expected| >= drift_threshold_ms, emit
---   { delta_ms = actual - expected } and reset the reference points so
---   subsequent ticks don't keep re-emitting the same drift.
---
--- Every value the tick needs (`get_monotonic_ms`, `get_wall_ms`, `emit`) is
--- injected, so the drift-computation logic is testable as a pure function
--- via the exposed `handle._tick()`, separately from the real `vim.uv` timer
--- (mirrors heartbeat.lua / CLAUDE.md's "test the event-to-log-entry
--- transform as a pure function, separately from the editor wiring").

local M = {}

local DEFAULT_INTERVAL_MS = 1000
local DEFAULT_DRIFT_THRESHOLD_MS = 500

local function default_get_monotonic_ms()
  return (vim.uv or vim.loop).hrtime() / 1e6
end

local function default_get_wall_ms()
  local s, us = (vim.uv or vim.loop).gettimeofday()
  return s * 1000 + us / 1000
end

--- start(opts) -> handle
--- @param opts table {
---   interval_ms?: number (default 1000),
---   drift_threshold_ms?: number (default 500),
---   emit: function(kind, data)              -- SessionHost.emit
---   get_monotonic_ms?: function() -> number (ms)
---   get_wall_ms?: function() -> number (ms)
--- }
--- @return table handle { dispose(), _tick() }
function M.start(opts)
  opts = opts or {}

  local interval_ms = opts.interval_ms or DEFAULT_INTERVAL_MS
  local drift_threshold_ms = opts.drift_threshold_ms or DEFAULT_DRIFT_THRESHOLD_MS
  local emit = opts.emit
  local get_monotonic_ms = opts.get_monotonic_ms or default_get_monotonic_ms
  local get_wall_ms = opts.get_wall_ms or default_get_wall_ms

  local disposed = false

  -- Capture reference points at start.
  local t0_monotonic = get_monotonic_ms()
  local t0_wall = get_wall_ms()

  local handle = {}

  --- Compute drift and emit one `clock.skew` if it exceeds the threshold.
  --- Exposed as `handle._tick()` so tests can drive ticks deterministically
  --- without relying on real wall-clock timer firing.
  function handle._tick()
    if disposed then
      return
    end

    local now = get_monotonic_ms()
    local now_wall = get_wall_ms()

    local expected = now - t0_monotonic -- how much monotonic time elapsed
    local actual = now_wall - t0_wall -- how much wall time elapsed
    local drift = actual - expected

    if math.abs(drift) >= drift_threshold_ms then
      emit("clock.skew", { delta_ms = drift })
      -- Reset so we don't keep emitting on the same drift.
      t0_monotonic = now
      t0_wall = now_wall
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
  -- A pending check must never keep Neovim from exiting.
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
