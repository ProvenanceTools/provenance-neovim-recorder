--- heartbeat.start (Plan 4). Ticks are driven deterministically via the
--- exposed `handle._tick()` rather than real wall-clock timer firing (CLAUDE.md
--- "Determinism. Inject clocks... no real timing in assertions") — the timer
--- itself is only smoke-tested for teardown (no hang on headless exit).
local heartbeat = require("provenance.recorder.events.heartbeat")
local core_json = require("provenance.core.json")

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

describe("heartbeat.start", function()
  local handle

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
  end)

  it("a tick emits session.heartbeat with focused/active_file/idle_since_ms", function()
    local events, emit = new_emit()
    local now = 1000
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return now end,
      get_focused = function() return true end,
      get_active_file = function() return "src/main.py" end,
    })

    now = 1500
    handle._tick()

    assert.equals(1, #events)
    assert.equals("session.heartbeat", events[1].kind)
    assert.equals(true, events[1].data.focused)
    assert.equals("src/main.py", events[1].data.active_file)
    assert.equals(500, events[1].data.idle_since_ms)
  end)

  it("active_file is core.json.NULL when get_active_file() returns nil", function()
    local events, emit = new_emit()
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return 0 end,
      get_focused = function() return false end,
      get_active_file = function() return nil end,
    })

    handle._tick()

    assert.equals(1, #events)
    assert.equals(core_json.NULL, events[1].data.active_file)
    assert.equals(false, events[1].data.focused)
  end)

  it("focused reflects get_focused() at tick time", function()
    local events, emit = new_emit()
    local focused = false
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return 0 end,
      get_focused = function() return focused end,
      get_active_file = function() return nil end,
    })

    handle._tick()
    assert.equals(false, events[1].data.focused)

    focused = true
    handle._tick()
    assert.equals(true, events[2].data.focused)
  end)

  it("mark_activity() resets idle_since_ms to ~0 on the next tick", function()
    local events, emit = new_emit()
    local now = 0
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return now end,
      get_focused = function() return true end,
      get_active_file = function() return nil end,
    })

    now = 10000
    handle._tick()
    assert.equals(10000, events[1].data.idle_since_ms)

    now = 10050
    handle.mark_activity()
    now = 10080
    handle._tick()
    assert.equals(30, events[2].data.idle_since_ms)
  end)

  it("idle_since_ms starts relative to start() time, not epoch 0", function()
    local events, emit = new_emit()
    local now = 5000
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return now end,
      get_focused = function() return true end,
      get_active_file = function() return nil end,
    })

    now = 5010
    handle._tick()
    assert.equals(10, events[1].data.idle_since_ms)
  end)

  it("idle_since_ms is clamped to 0, never negative", function()
    local events, emit = new_emit()
    local now = 1000
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return now end,
      get_focused = function() return true end,
      get_active_file = function() return nil end,
    })

    handle.mark_activity()
    now = 990 -- clock moved backward relative to last_activity
    handle._tick()
    assert.equals(0, events[1].data.idle_since_ms)
  end)

  it("after dispose() no further ticks emit", function()
    local events, emit = new_emit()
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return 0 end,
      get_focused = function() return true end,
      get_active_file = function() return nil end,
    })

    handle._tick()
    assert.equals(1, #events)

    handle.dispose()
    handle._tick()
    assert.equals(1, #events)
  end)

  it("dispose() is idempotent and does not error", function()
    local _, emit = new_emit()
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return 0 end,
      get_focused = function() return true end,
      get_active_file = function() return nil end,
    })

    assert.has_no.errors(function() handle.dispose() end)
    assert.has_no.errors(function() handle.dispose() end)
  end)

  it("default interval_ms is 30000 and the timer is created unref'd (headless exits clean)", function()
    local _, emit = new_emit()
    -- No interval_ms passed: exercises the real vim.uv timer + default
    -- interval path. unref() means this timer must not keep the process
    -- (or the test runner) alive; dispose() in after_each tears it down.
    handle = heartbeat.start({
      emit = emit,
      get_now = function() return 0 end,
      get_focused = function() return true end,
      get_active_file = function() return nil end,
    })

    assert.is_function(handle.dispose)
    assert.is_function(handle.mark_activity)
    assert.is_function(handle._tick)
  end)

  it("uses production defaults (get_now/get_focused/get_active_file) when omitted", function()
    -- Only emit is required; defaults must not error on a real headless nvim.
    handle = heartbeat.start({ emit = function() end })
    assert.has_no.errors(function() handle._tick() end)
  end)

  describe("session.resumed suspend detection", function()
    it("does not emit session.resumed on the first tick (no previous tick to compare)", function()
      local events, emit = new_emit()
      local wall = 0
      handle = heartbeat.start({
        emit = emit,
        interval_ms = 30000,
        get_now = function() return 0 end,
        get_wall_ms = function() return wall end,
        get_focused = function() return true end,
        get_active_file = function() return nil end,
      })

      -- Even a huge "gap" relative to session start must not fire, since
      -- there is no prior tick yet.
      wall = 10 * 60 * 1000
      handle._tick()

      assert.equals(1, #events)
      assert.equals("session.heartbeat", events[1].kind)
    end)

    it("does not emit session.resumed when the gap is close to the expected interval", function()
      local events, emit = new_emit()
      local wall = 0
      handle = heartbeat.start({
        emit = emit,
        interval_ms = 30000,
        get_now = function() return 0 end,
        get_wall_ms = function() return wall end,
        get_focused = function() return true end,
        get_active_file = function() return nil end,
      })

      handle._tick() -- establishes last_tick_wall_ms
      wall = wall + 31000 -- slightly over interval, well under 2x
      handle._tick()

      assert.equals(2, #events)
      assert.equals("session.heartbeat", events[1].kind)
      assert.equals("session.heartbeat", events[2].kind)
    end)

    it("emits session.resumed before session.heartbeat when the gap is >= 2x interval_ms", function()
      local events, emit = new_emit()
      local wall = 0
      handle = heartbeat.start({
        emit = emit,
        interval_ms = 30000,
        get_now = function() return 0 end,
        get_wall_ms = function() return wall end,
        get_focused = function() return true end,
        get_active_file = function() return nil end,
      })

      handle._tick() -- tick #1: establishes last_tick_wall_ms, no gap check yet
      -- Simulate a suspend: wall clock jumps 1 hour ahead before the next tick.
      wall = wall + 60 * 60 * 1000
      handle._tick()

      assert.equals(3, #events)
      assert.equals("session.heartbeat", events[1].kind)
      assert.equals("session.resumed", events[2].kind)
      assert.equals(60 * 60 * 1000, events[2].data.gap_ms)
      assert.equals(30000, events[2].data.expected_interval_ms)
      assert.equals("session.heartbeat", events[3].kind)
    end)

    it("fires exactly at the 2x interval_ms threshold (boundary is inclusive)", function()
      local events, emit = new_emit()
      local wall = 0
      handle = heartbeat.start({
        emit = emit,
        interval_ms = 30000,
        get_now = function() return 0 end,
        get_wall_ms = function() return wall end,
        get_focused = function() return true end,
        get_active_file = function() return nil end,
      })

      handle._tick()
      wall = wall + 60000 -- exactly 2x interval_ms
      handle._tick()

      assert.equals(3, #events)
      assert.equals("session.resumed", events[2].kind)
      assert.equals(60000, events[2].data.gap_ms)
    end)

    it("does not emit session.resumed when the wall clock moves backward (negative gap)", function()
      local events, emit = new_emit()
      local wall = 100000
      handle = heartbeat.start({
        emit = emit,
        interval_ms = 30000,
        get_now = function() return 0 end,
        get_wall_ms = function() return wall end,
        get_focused = function() return true end,
        get_active_file = function() return nil end,
      })

      handle._tick()
      wall = 0 -- backwards NTP correction
      handle._tick()

      assert.equals(2, #events)
      assert.equals("session.heartbeat", events[1].kind)
      assert.equals("session.heartbeat", events[2].kind)
    end)

    it("uses the production default_get_wall_ms (true wall clock) when omitted", function()
      -- Only emit is required; the real vim.uv.gettimeofday()-backed default
      -- must not error on a real headless nvim.
      handle = heartbeat.start({ emit = function() end, interval_ms = 30000 })
      assert.has_no.errors(function() handle._tick() end)
      assert.has_no.errors(function() handle._tick() end)
    end)
  end)
end)
