--- ext_activation_wiring: polls the loaded-plugin set and emits ext.activate
--- for plugins that appear AFTER session start, mirroring VS Code's
--- extension-activation poller (no public activation event exists there
--- either). Deterministic via the injected list_plugins + handle._tick().
local ext_activation = require("provenance.recorder.wiring.ext_activation_wiring")

local function new_emit()
  local events = {}
  return events, function(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
end

local function count(events, kind)
  local n = 0
  for _, ev in ipairs(events) do
    if ev.kind == kind then
      n = n + 1
    end
  end
  return n
end

describe("ext_activation_wiring.start", function()
  local handle

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
  end)

  it("emits nothing for the baseline plugins present at start", function()
    local events, emit = new_emit()
    handle = ext_activation.start({
      emit = emit,
      list_plugins = function()
        return { { id = "plenary.nvim", version = "", enabled = true } }
      end,
    })
    assert.equals(0, count(events, "ext.activate"))
  end)

  it("emits ext.activate for a plugin that appears after start", function()
    local current = { { id = "plenary.nvim", version = "", enabled = true } }
    local events, emit = new_emit()
    handle = ext_activation.start({
      emit = emit,
      list_plugins = function()
        return current
      end,
    })

    table.insert(current, { id = "telescope.nvim", version = "1.2.3", enabled = true })
    handle._tick()

    assert.equals(1, count(events, "ext.activate"))
    assert.equals("telescope.nvim", events[1].data.id)
    assert.equals("1.2.3", events[1].data.version)
  end)

  it("does not re-emit an already-activated plugin", function()
    local current = {}
    local events, emit = new_emit()
    handle = ext_activation.start({
      emit = emit,
      list_plugins = function()
        return current
      end,
    })

    table.insert(current, { id = "new.nvim", version = "", enabled = true })
    handle._tick()
    handle._tick()

    assert.equals(1, count(events, "ext.activate"))
  end)

  it("dispose() stops further activation emits and is idempotent", function()
    local current = {}
    local events, emit = new_emit()
    handle = ext_activation.start({
      emit = emit,
      list_plugins = function()
        return current
      end,
    })

    handle.dispose()
    table.insert(current, { id = "late.nvim", version = "", enabled = true })
    handle._tick()
    assert.equals(0, count(events, "ext.activate"))

    assert.has_no.errors(function()
      handle.dispose()
    end)
  end)

  it("default interval + timer is unref'd (headless exits clean)", function()
    local events, emit = new_emit()
    handle = ext_activation.start({
      emit = emit,
      list_plugins = function()
        return {}
      end,
    })
    -- No interval_ms passed: exercises the real vim.uv timer path.
    assert.equals(0, count(events, "ext.activate"))
  end)
end)
