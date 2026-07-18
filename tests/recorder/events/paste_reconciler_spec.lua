--- paste_reconciler.start (Plan 6, Task 4) — signal 3's reconciliation: an
--- interval watchdog comparing intercepted-paste counts vs large-insert
--- classification counts, emitting paste.anomaly when they diverge beyond
--- tolerance. Ticks are driven deterministically via the exposed
--- `handle._tick()` (mirrors heartbeat_spec.lua) rather than real
--- wall-clock timer firing.
local paste_reconciler = require("provenance.recorder.events.paste_reconciler")

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

--- Returns mutable counters plus their getters, so tests can drive
--- `i_count`/`l_count` between ticks without a real correlator.
local function new_counts()
  local i_count = 0
  local l_count = 0
  return {
    get_intercepted_count = function() return i_count end,
    get_large_insert_count = function() return l_count end,
    set = function(i, l)
      i_count = i
      l_count = l
    end,
  }
end

describe("paste_reconciler.start", function()
  local handle

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
  end)

  it("equal deltas -> no emit", function()
    local events, emit = new_emit()
    local counts = new_counts()
    handle = paste_reconciler.start({
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    counts.set(3, 3)
    handle._tick()

    assert.equals(0, #events)
  end)

  it("|2-3|=1 is not > default tolerance(1) -> no emit", function()
    local events, emit = new_emit()
    local counts = new_counts()
    handle = paste_reconciler.start({
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    counts.set(2, 3)
    handle._tick()

    assert.equals(0, #events)
  end)

  it("|1-4|=3 > tolerance -> emits paste.anomaly with per-interval deltas", function()
    local events, emit = new_emit()
    local counts = new_counts()
    handle = paste_reconciler.start({
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    counts.set(1, 4)
    handle._tick()

    assert.equals(1, #events)
    assert.equals("paste.anomaly", events[1].kind)
    assert.equals(1, events[1].data.intercepted_count)
    assert.equals(4, events[1].data.large_insert_count)
  end)

  it("tolerance=0 with +2 vs +3 -> emits {2,3}", function()
    local events, emit = new_emit()
    local counts = new_counts()
    handle = paste_reconciler.start({
      tolerance = 0,
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    counts.set(2, 3)
    handle._tick()

    assert.equals(1, #events)
    assert.equals("paste.anomaly", events[1].kind)
    assert.equals(2, events[1].data.intercepted_count)
    assert.equals(3, events[1].data.large_insert_count)
  end)

  it("baseline resets after each tick: same cumulative counts don't re-trigger, deltas measured from new baseline", function()
    local events, emit = new_emit()
    local counts = new_counts()
    handle = paste_reconciler.start({
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    counts.set(1, 4)
    handle._tick()
    assert.equals(1, #events)
    assert.equals(1, events[1].data.intercepted_count)
    assert.equals(4, events[1].data.large_insert_count)

    -- No further change in cumulative counts -> deltas are 0/0 -> no emit.
    counts.set(1, 4)
    handle._tick()
    assert.equals(1, #events)

    -- New change measured from the NEW baseline (1, 4), not from 0.
    counts.set(1, 6)
    handle._tick()
    assert.equals(2, #events)
    assert.equals("paste.anomaly", events[2].kind)
    assert.equals(0, events[2].data.intercepted_count)
    assert.equals(2, events[2].data.large_insert_count)
  end)

  it("after dispose() no further ticks emit", function()
    local events, emit = new_emit()
    local counts = new_counts()
    handle = paste_reconciler.start({
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    handle.dispose()
    counts.set(10, 0)
    handle._tick()

    assert.equals(0, #events)
  end)

  it("dispose() is idempotent and does not error", function()
    local _, emit = new_emit()
    local counts = new_counts()
    handle = paste_reconciler.start({
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    assert.has_no.errors(function() handle.dispose() end)
    assert.has_no.errors(function() handle.dispose() end)
  end)

  it("default interval_ms creates an unref'd real timer (headless exits clean)", function()
    local _, emit = new_emit()
    local counts = new_counts()
    -- No interval_ms passed: exercises the real vim.uv timer + default
    -- interval path. unref() means this timer must not keep the process
    -- (or the test runner) alive; dispose() in after_each tears it down.
    handle = paste_reconciler.start({
      emit = emit,
      get_intercepted_count = counts.get_intercepted_count,
      get_large_insert_count = counts.get_large_insert_count,
    })

    assert.is_function(handle.dispose)
    assert.is_function(handle._tick)
  end)
end)
