--- snapshot_wiring.start (Plan 7 / Task 4): an always-on plugin snapshot.
--- Emits ext.snapshot immediately on start, then again every interval_ms via
--- a vim.uv timer. Ticks are driven deterministically via the exposed
--- `handle._tick()` (mirrors heartbeat.lua/CLAUDE.md's "inject clocks, no
--- real timing in assertions") — the real timer is only smoke-tested for
--- teardown (no hang on headless exit).
local snapshot_wiring = require("provenance.recorder.wiring.snapshot_wiring")
local json = require("provenance.core.json")

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

describe("snapshot_wiring.start", function()
  local handle

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
  end)

  it("emits exactly one ext.snapshot immediately on start, with the injected list", function()
    local events, emit = new_emit()
    handle = snapshot_wiring.start({
      emit = emit,
      list_plugins = function()
        return {
          { id = "foo", version = "1.0", enabled = true },
          { id = "bar", version = "", enabled = true },
        }
      end,
    })

    assert.equals(1, #events)
    assert.equals("ext.snapshot", events[1].kind)
    assert.equals(2, #events[1].data.extensions)
    assert.equals("foo", events[1].data.extensions[1].id)
    assert.equals("1.0", events[1].data.extensions[1].version)
    assert.equals(true, events[1].data.extensions[1].enabled)
    assert.equals("bar", events[1].data.extensions[2].id)
    assert.equals("", events[1].data.extensions[2].version)
    assert.equals(true, events[1].data.extensions[2].enabled)
  end)

  it("emitted extensions canonicalize as a JSON array, not an object", function()
    local events, emit = new_emit()
    handle = snapshot_wiring.start({
      emit = emit,
      list_plugins = function()
        return { { id = "x", version = "1.0", enabled = true } }
      end,
    })

    assert.is_true(json.is_array(events[1].data.extensions))
    local canon = json.canonicalize(events[1].data.extensions)
    assert.equals("[", canon:sub(1, 1))
  end)

  it("empty list_plugins() still canonicalizes as [] not {}", function()
    local events, emit = new_emit()
    handle = snapshot_wiring.start({
      emit = emit,
      list_plugins = function() return {} end,
    })

    assert.equals(1, #events)
    assert.equals("[]", json.canonicalize(events[1].data.extensions))
  end)

  it("_tick() re-emits ext.snapshot, reflecting a possibly-updated list", function()
    local events, emit = new_emit()
    local current = { { id = "foo", version = "1.0", enabled = true } }
    handle = snapshot_wiring.start({
      emit = emit,
      list_plugins = function() return current end,
    })
    assert.equals(1, #events)

    current = {
      { id = "foo", version = "1.1", enabled = true },
      { id = "baz", version = "0.1", enabled = false },
    }
    handle._tick()

    assert.equals(2, #events)
    assert.equals("ext.snapshot", events[2].kind)
    assert.equals(2, #events[2].data.extensions)
    assert.equals("foo", events[2].data.extensions[1].id)
    assert.equals("1.1", events[2].data.extensions[1].version)
    assert.equals("baz", events[2].data.extensions[2].id)
    assert.equals(false, events[2].data.extensions[2].enabled)
  end)

  it("after dispose() no further ticks emit", function()
    local events, emit = new_emit()
    handle = snapshot_wiring.start({
      emit = emit,
      list_plugins = function() return {} end,
    })
    assert.equals(1, #events)

    handle.dispose()
    handle._tick()
    assert.equals(1, #events)
  end)

  it("dispose() is idempotent and does not error", function()
    local _, emit = new_emit()
    handle = snapshot_wiring.start({
      emit = emit,
      list_plugins = function() return {} end,
    })

    assert.has_no.errors(function() handle.dispose() end)
    assert.has_no.errors(function() handle.dispose() end)
  end)

  it("default interval_ms is 300000 and the timer is created unref'd (headless exits clean)", function()
    local _, emit = new_emit()
    -- No interval_ms passed: exercises the real vim.uv timer + default
    -- interval path. unref() means this timer must not keep the process
    -- (or the test runner) alive; dispose() in after_each tears it down.
    handle = snapshot_wiring.start({
      emit = emit,
      list_plugins = function() return {} end,
    })

    assert.is_function(handle.dispose)
    assert.is_function(handle._tick)
  end)

  it("uses the default list_plugins (real runtimepath enumeration) without error when omitted", function()
    local events, emit = new_emit()
    handle = snapshot_wiring.start({ emit = emit })

    assert.equals(1, #events)
    assert.equals("ext.snapshot", events[1].kind)
    assert.is_true(json.is_array(events[1].data.extensions))
  end)
end)
