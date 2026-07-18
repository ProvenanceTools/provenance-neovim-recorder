--- clock_skew_watcher.start (Plan 9). Ticks are driven deterministically via
--- the exposed `handle._tick()` rather than real wall-clock timer firing
--- (CLAUDE.md "Determinism. Inject clocks... no real timing in assertions")
--- — the timer itself is only smoke-tested for teardown (no hang on headless
--- exit). Faithful port of clock-watcher.ts.
local clock_skew_watcher = require("provenance.recorder.events.clock_skew_watcher")

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

describe("clock_skew_watcher.start", function()
  local handle

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
  end)

  it("no skew: wall tracks monotonic exactly -> no emit", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    monotonic = monotonic + 1000
    wall = wall + 1000
    handle._tick()

    assert.equals(0, #events)
  end)

  it("drift below threshold does not emit", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    monotonic = monotonic + 1000
    wall = wall + 1400 -- drift 400 < 500
    handle._tick()

    assert.equals(0, #events)
  end)

  it("forward drift at/above threshold emits clock.skew with positive delta_ms", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    monotonic = monotonic + 1000
    wall = wall + 1600 -- drift 600 >= 500
    handle._tick()

    assert.equals(1, #events)
    assert.equals("clock.skew", events[1].kind)
    assert.equals(600, events[1].data.delta_ms)
  end)

  it("backward drift emits clock.skew with negative delta_ms preserved", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    monotonic = monotonic + 1000
    wall = wall + 300 -- drift -700, abs 700 >= 500
    handle._tick()

    assert.equals(1, #events)
    assert.equals("clock.skew", events[1].kind)
    assert.equals(-700, events[1].data.delta_ms)
  end)

  it("resets reference points after an emit so the same drift is not re-emitted", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    monotonic = monotonic + 1000
    wall = wall + 1600 -- drift 600 >= 500 -> emit, refs reset to (1000, 1600)
    handle._tick()
    assert.equals(1, #events)

    -- Wall now tracks monotonic again from the reset reference point: no NEW drift.
    monotonic = monotonic + 1000
    wall = wall + 1000
    handle._tick()
    assert.equals(1, #events) -- no re-emit
  end)

  it("threshold boundary is inclusive (>=), drift exactly at threshold emits", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      drift_threshold_ms = 500,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    monotonic = monotonic + 1000
    wall = wall + 1500 -- drift exactly 500
    handle._tick()

    assert.equals(1, #events)
    assert.equals(500, events[1].data.delta_ms)
  end)

  it("respects a custom drift_threshold_ms", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      drift_threshold_ms = 100,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    monotonic = monotonic + 1000
    wall = wall + 1150 -- drift 150 >= 100
    handle._tick()

    assert.equals(1, #events)
    assert.equals(150, events[1].data.delta_ms)
  end)

  it("after dispose() no further ticks emit", function()
    local events, emit = new_emit()
    local monotonic = 0
    local wall = 0
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return monotonic end,
      get_wall_ms = function() return wall end,
    })

    handle.dispose()

    monotonic = monotonic + 1000
    wall = wall + 2000
    handle._tick()

    assert.equals(0, #events)
  end)

  it("dispose() is idempotent and does not error", function()
    local _, emit = new_emit()
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return 0 end,
      get_wall_ms = function() return 0 end,
    })

    assert.has_no.errors(function() handle.dispose() end)
    assert.has_no.errors(function() handle.dispose() end)
  end)

  it("default interval_ms/drift_threshold_ms and unref'd timer (headless exits clean)", function()
    local _, emit = new_emit()
    -- No interval_ms passed: exercises the real vim.uv timer + defaults.
    -- unref() means this timer must not keep the process (or the test
    -- runner) alive; dispose() in after_each tears it down.
    handle = clock_skew_watcher.start({
      emit = emit,
      get_monotonic_ms = function() return 0 end,
      get_wall_ms = function() return 0 end,
    })

    assert.is_function(handle.dispose)
    assert.is_function(handle._tick)
  end)

  it("uses production defaults (get_monotonic_ms/get_wall_ms) when omitted", function()
    -- Only emit is required; defaults must not error on a real headless nvim.
    handle = clock_skew_watcher.start({ emit = function() end })
    assert.has_no.errors(function() handle._tick() end)
  end)
end)
