--- Activation bootstrap wiring (design.md §5, task 6): setup() ties
--- activation.load_and_verify + state + status together behind a
--- VimEnter/DirChanged autocmd, with an injectable loader so this spec never
--- touches the filesystem. Mirrors the injected-fake style of
--- activation_loader_spec.lua but at the recorder.setup() seam.
local status = require("provenance.recorder.status")

describe("recorder.setup", function()
  -- recorder.init is required fresh in each test via package.loaded reset so
  -- module-level `state` doesn't leak identity across tests (the augroup
  -- name and status singleton are what CLAUDE.md/task brief warn about).
  local recorder

  before_each(function()
    package.loaded["provenance.recorder"] = nil
    package.loaded["provenance.recorder.init"] = nil
    recorder = require("provenance.recorder")
  end)

  local handle

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
    -- Belt-and-suspenders: status is a module-level singleton: make sure no
    -- test leaks an attached state into the next one even if dispose() was
    -- somehow skipped above.
    status.detach()
  end)

  it("active loader: state becomes active and status segment is non-empty", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "active", root = "/tmp/ws", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = function()
        return { seal = function() end, stop = function() end }
      end,
    })

    local segment = status.segment()
    assert.is_not.equals("", segment)
    assert.is_not_nil(string.find(segment, "recording"))
  end)

  it("active loader: the Provenance augroup exists with autocmds registered", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "active", root = "/tmp/ws", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = function()
        return { seal = function() end, stop = function() end }
      end,
    })

    local autocmds = vim.api.nvim_get_autocmds({ group = "Provenance" })
    assert.is_true(#autocmds > 0)
  end)

  it("inactive loader: status segment is empty", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "inactive", reason = "no_manifest_file" }
      end,
    })

    assert.equals("", status.segment())
  end)

  it("inactive loader: :ProvenanceSeal command is registered", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "inactive", reason = "no_manifest_file" }
      end,
    })

    assert.equals(2, vim.fn.exists(":ProvenanceSeal"))
  end)

  it("inactive loader: invoking :ProvenanceSeal records nothing and does not error", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "inactive", reason = "no_manifest_file" }
      end,
    })

    local ok = pcall(vim.cmd, "ProvenanceSeal")
    assert.is_true(ok)
    -- Still inactive: the stub must not have activated anything.
    assert.equals("", status.segment())
  end)

  it("dispose(): removes the Provenance augroup", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "active", root = "/tmp/ws", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = function()
        return { seal = function() end, stop = function() end }
      end,
    })

    handle.dispose()
    handle = nil

    local ok, result = pcall(vim.api.nvim_get_autocmds, { group = "Provenance" })
    if ok then
      assert.equals(0, #result)
    else
      -- nvim_get_autocmds errors when the named group no longer exists —
      -- also acceptable proof the group is gone.
      assert.is_true(true)
    end
  end)

  it("inactive loader: debug gate off (default) emits no visible notification", function()
    local calls = {}
    local orig_notify = vim.notify
    vim.notify = function(...)
      table.insert(calls, { ... })
    end

    local ok = pcall(function()
      handle = recorder.setup({
        workspace = "/tmp/ws",
        load_and_verify = function()
          return { status = "inactive", reason = "no_manifest_file" }
        end,
      })
    end)

    vim.notify = orig_notify

    assert.is_true(ok)
    assert.equals(0, #calls)
  end)

  it("inactive loader: debug gate on (vim.g.provenance_debug) emits a notification", function()
    vim.g.provenance_debug = true

    local calls = {}
    local orig_notify = vim.notify
    vim.notify = function(...)
      table.insert(calls, { ... })
    end

    local ok = pcall(function()
      handle = recorder.setup({
        workspace = "/tmp/ws",
        load_and_verify = function()
          return { status = "inactive", reason = "no_manifest_file" }
        end,
      })
    end)

    vim.notify = orig_notify
    vim.g.provenance_debug = nil

    assert.is_true(ok)
    assert.is_true(#calls >= 1)
  end)

  it("dispose(): detaches status so segment() goes back to empty", function()
    handle = recorder.setup({
      workspace = "/tmp/ws",
      resolve = function()
        return { status = "active", root = "/tmp/ws", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = function()
        return { seal = function() end, stop = function() end }
      end,
    })
    assert.is_not.equals("", status.segment())

    handle.dispose()
    handle = nil

    assert.equals("", status.segment())
  end)
end)
