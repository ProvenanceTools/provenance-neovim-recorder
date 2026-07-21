--- Tests for registry.lua: the root -> session map replacing the single
--- state/controller pair (Plan: 2026-07-20-nested-manifest-discovery).
--- Mirrors init_controller_spec.lua's injected start_recording spy style so
--- this never starts a real recording session or touches the filesystem.
local registry_mod = require("provenance.recorder.registry")

local function make_start_recording_spy()
  local calls = {}
  local function start_recording(args)
    local fake_controller = { stop_calls = {} }
    function fake_controller.stop(reason)
      table.insert(fake_controller.stop_calls, reason)
    end
    table.insert(calls, { args = args, controller = fake_controller })
    return fake_controller
  end
  return start_recording, calls
end

describe("registry.new", function()
  it("fresh registry: is_active() is false, list() is empty", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    assert.is_false(reg.is_active())
    assert.same({}, reg.list())
  end)

  it("ensure_session: starts a session with workspace/provenance_dir/manifest derived from root", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    local manifest = { assignment_id = "hw3" }

    local controller, started = reg.ensure_session("/tmp/ws-a", manifest)

    assert.is_true(started)
    assert.is_not_nil(controller)
    assert.equals(1, #calls)
    assert.equals("/tmp/ws-a", calls[1].args.workspace)
    assert.equals("/tmp/ws-a/.provenance", calls[1].args.provenance_dir)
    assert.equals(manifest, calls[1].args.manifest)
    assert.is_true(reg.is_active())
    assert.is_true(reg.has_session("/tmp/ws-a"))
  end)

  it("ensure_session is idempotent: a second call for the SAME root does not start a second session", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    local manifest = { assignment_id = "hw3" }

    local c1, started1 = reg.ensure_session("/tmp/ws-a", manifest)
    local c2, started2 = reg.ensure_session("/tmp/ws-a", manifest)

    assert.equals(1, #calls)
    assert.is_true(started1)
    assert.is_false(started2)
    assert.equals(c1, c2)
  end)

  it("CONCURRENCY: two different roots each get their own session", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })

    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    assert.equals(2, #calls)
    assert.is_true(reg.has_session("/tmp/cats"))
    assert.is_true(reg.has_session("/tmp/hog"))
    assert.is_true(reg.is_active())

    local list = reg.list()
    assert.equals(2, #list)
    -- Sorted by root ascending.
    assert.equals("/tmp/cats", list[1].root)
    assert.equals("/tmp/hog", list[2].root)
  end)

  it("get(root) returns the stored entry; get() for an unknown root returns nil", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })

    local entry = reg.get("/tmp/cats")
    assert.equals("cats", entry.manifest.assignment_id)
    assert.equals("/tmp/cats/.provenance", entry.provenance_dir)

    assert.is_nil(reg.get("/tmp/nonexistent"))
  end)

  it("ensure_session propagates extra_opts to start_recording, extra_opts winning on conflicts", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })

    reg.ensure_session("/tmp/cats", { assignment_id = "cats" }, { clock = "injected-clock", provenance_dir = "/tmp/cats/.override" })

    assert.equals("injected-clock", calls[1].args.clock)
    assert.equals("/tmp/cats/.override", calls[1].args.provenance_dir)
  end)

  it("ensure_session on a start_recording failure does not register a half-open entry", function()
    local reg = registry_mod.new({
      start_recording = function()
        error("boom")
      end,
    })

    local controller, started, err = reg.ensure_session("/tmp/cats", { assignment_id = "cats" })

    assert.is_nil(controller)
    assert.is_false(started)
    assert.is_not_nil(err)
    assert.is_false(reg.has_session("/tmp/cats"))
    assert.is_false(reg.is_active())
  end)

  it("stop_all: stops every session exactly once and clears the registry", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    reg.stop_all("deactivate")

    assert.equals(1, #calls[1].controller.stop_calls)
    assert.equals("deactivate", calls[1].controller.stop_calls[1])
    assert.equals(1, #calls[2].controller.stop_calls)
    assert.is_false(reg.is_active())
    assert.same({}, reg.list())
  end)

  it("stop_all is safe to call with zero active sessions", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    assert.has_no.errors(function()
      reg.stop_all("deactivate")
    end)
  end)

  it("stop_all does not stop the SAME controller twice if a controller.stop() call throws", function()
    local reg = registry_mod.new({
      start_recording = function()
        return { stop = function() error("stop failed") end }
      end,
    })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    -- A throwing stop() for one entry must not prevent the OTHER entry
    -- from being stopped and cleared too.
    assert.has_no.errors(function()
      reg.stop_all("deactivate")
    end)
    assert.is_false(reg.is_active())
  end)
end)
