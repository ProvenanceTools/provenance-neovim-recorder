--- Live :ProvenanceSeal command wiring (Plan 9, task 3): on a genuine
--- activation the inert stub registered by resolve_and_apply's INACTIVE
--- branch is replaced by a LIVE command that calls controller.seal() and
--- surfaces the result via vim.notify (INFO on success, WARN on
--- chain_broken/no_sessions, ERROR on write_error/exception). Mirrors the
--- injected-fake harness style of init_controller_spec.lua: opts.start_recording
--- returns a fake controller so this spec never touches the filesystem.
local status = require("provenance.recorder.status")

--- Builds a start_recording seam that always returns the given fake
--- controller (so tests can control what controller.seal() returns).
--- @param fake_controller table
--- @return function start_recording
local function make_start_recording(fake_controller)
  return function()
    return fake_controller
  end
end

--- Monkeypatches vim.notify to capture (message, level) pairs. Caller must
--- restore via the returned `restore()` in after_each.
--- @return table calls, function restore
local function capture_notify()
  local calls = {}
  local orig_notify = vim.notify
  vim.notify = function(message, level, ...)
    table.insert(calls, { message = message, level = level })
  end
  return calls, function()
    vim.notify = orig_notify
  end
end

describe("recorder.setup :ProvenanceSeal live command", function()
  local recorder

  before_each(function()
    package.loaded["provenance.recorder"] = nil
    package.loaded["provenance.recorder.init"] = nil
    recorder = require("provenance.recorder")
  end)

  local handle
  local restore_notify

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
    if restore_notify then
      restore_notify()
      restore_notify = nil
    end
    status.detach()
  end)

  it("active session: :ProvenanceSeal calls controller.seal() and notifies the bundle path at INFO", function()
    local seal_calls = 0
    local fake_controller = {
      seal = function()
        seal_calls = seal_calls + 1
        return {
          kind = "ok",
          bundle_path = "/tmp/hw3-bundle.zip",
          manifest_sha256 = "deadbeef",
          warnings = { chain_broken = false, unreadable_session = false },
        }
      end,
      stop = function() end,
    }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = make_start_recording(fake_controller),
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(1, seal_calls)
    assert.equals(1, #calls)
    assert.equals(vim.log.levels.INFO, calls[1].level)
    assert.is_not_nil(string.find(calls[1].message, "/tmp/hw3-bundle.zip", 1, true))
  end)

  it("active session: chain_broken warning notifies at WARN with WARNINGS + path", function()
    local fake_controller = {
      seal = function()
        return {
          kind = "ok",
          bundle_path = "/tmp/hw3-bundle.zip",
          warnings = { chain_broken = true, unreadable_session = false },
        }
      end,
      stop = function() end,
    }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = make_start_recording(fake_controller),
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(1, #calls)
    assert.equals(vim.log.levels.WARN, calls[1].level)
    assert.is_not_nil(string.find(calls[1].message, "WARNINGS", 1, true))
    assert.is_not_nil(string.find(calls[1].message, "/tmp/hw3-bundle.zip", 1, true))
  end)

  it("active session: no_sessions result notifies WARN 'nothing to seal'", function()
    local fake_controller = {
      seal = function()
        return { kind = "no_sessions" }
      end,
      stop = function() end,
    }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = make_start_recording(fake_controller),
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(1, #calls)
    assert.equals(vim.log.levels.WARN, calls[1].level)
    assert.is_not_nil(string.find(calls[1].message, "nothing to seal", 1, true))
  end)

  it("active session: write_error result notifies ERROR containing the message", function()
    local fake_controller = {
      seal = function()
        return { kind = "write_error", message = "disk full" }
      end,
      stop = function() end,
    }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = make_start_recording(fake_controller),
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(1, #calls)
    assert.equals(vim.log.levels.ERROR, calls[1].level)
    assert.is_not_nil(string.find(calls[1].message, "disk full", 1, true))
  end)

  it("active session: controller.seal() throwing notifies ERROR and does not propagate", function()
    local fake_controller = {
      seal = function()
        error("boom")
      end,
      stop = function() end,
    }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = make_start_recording(fake_controller),
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    local ok = pcall(vim.cmd, "ProvenanceSeal")

    assert.is_true(ok)
    assert.equals(1, #calls)
    assert.equals(vim.log.levels.ERROR, calls[1].level)
  end)

  it("inactive workspace: :ProvenanceSeal shows the inert guidance message and never calls seal", function()
    local seal_calls = 0
    local start_recording_calls = 0
    local start_recording = function()
      start_recording_calls = start_recording_calls + 1
      return {
        seal = function()
          seal_calls = seal_calls + 1
          return { kind = "ok", bundle_path = "/tmp/should-not-happen.zip", warnings = {} }
        end,
        stop = function() end,
      }
    end

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = start_recording,
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(0, start_recording_calls)
    assert.equals(0, seal_calls)
    assert.equals(1, #calls)
    assert.equals(vim.log.levels.INFO, calls[1].level)
    assert.is_not_nil(string.find(calls[1].message, "not an activated assignment workspace", 1, true))
  end)

  it("dispose(): removes the live :ProvenanceSeal command entirely", function()
    local fake_controller = {
      seal = function()
        return { kind = "ok", bundle_path = "/tmp/x.zip", warnings = {} }
      end,
      stop = function() end,
    }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = make_start_recording(fake_controller),
    })

    assert.equals(2, vim.fn.exists(":ProvenanceSeal"))

    handle.dispose()
    handle = nil

    assert.equals(0, vim.fn.exists(":ProvenanceSeal"))
  end)
end)
