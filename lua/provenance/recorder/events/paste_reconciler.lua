--- Paste reconciler — signal 3 of three-signal paste detection (PRD §4.3).
---
--- Compares handler-intercepted paste counts against large-single-insert
--- classification counts on a rolling window. Mismatches (above tolerance)
--- emit `paste.anomaly` events. Faithful port of `paste-reconciler.ts`
--- (packages/recorder/src/events/paste-reconciler.ts).
---
--- Returns a handle whose `dispose()` clears the interval. The interval is
--- unref'd so it does not block Neovim exit (CLAUDE.md: "no background task
--- without an explicit teardown path"). Ticks are driven deterministically
--- via the exposed `handle._tick()` in tests (mirrors heartbeat.lua),
--- separately from the real `vim.uv` timer.

local M = {}

local DEFAULT_INTERVAL_MS = 5000
local DEFAULT_TOLERANCE = 1

--- start(opts) -> handle
--- @param opts table {
---   interval_ms?: number (default 5000),
---   tolerance?: number (default 1) -- counts within +/- tolerance are not anomalous
---   emit: function(kind, data)     -- SessionHost.emit; called as emit("paste.anomaly", data)
---   get_intercepted_count: function() -> number
---   get_large_insert_count: function() -> number
--- }
--- @return table handle { dispose(), _tick() }
function M.start(opts)
  opts = opts or {}

  local interval_ms = opts.interval_ms or DEFAULT_INTERVAL_MS
  local tolerance = opts.tolerance or DEFAULT_TOLERANCE
  local emit = opts.emit
  local get_intercepted_count = opts.get_intercepted_count
  local get_large_insert_count = opts.get_large_insert_count

  local disposed = false

  -- Capture baseline counts at start.
  local last_intercepted = get_intercepted_count()
  local last_large_insert = get_large_insert_count()

  local handle = {}

  --- Compute per-interval deltas and emit `paste.anomaly` when the
  --- discrepancy strictly exceeds tolerance. Exposed as `handle._tick()` so
  --- tests can drive ticks deterministically without relying on real
  --- wall-clock timer firing.
  function handle._tick()
    if disposed then
      return
    end

    local cur_intercepted = get_intercepted_count()
    local cur_large_insert = get_large_insert_count()

    local delta_intercepted = cur_intercepted - last_intercepted
    local delta_large_insert = cur_large_insert - last_large_insert

    -- Update baselines unconditionally (whether or not we emit).
    last_intercepted = cur_intercepted
    last_large_insert = cur_large_insert

    local discrepancy = math.abs(delta_intercepted - delta_large_insert)
    if discrepancy > tolerance then
      emit("paste.anomaly", {
        intercepted_count = delta_intercepted,
        large_insert_count = delta_large_insert,
      })
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
  -- A pending reconciliation tick must never keep Neovim from exiting.
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
