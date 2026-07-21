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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
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
      resolve = function()
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

  it("cd to an inactive directory does NOT stop or hide an already-active session: :ProvenanceSeal keeps sealing it (locked design: session lifetime is VimLeavePre/dispose, not cwd)", function()
    -- Repurposed from a pre-registry regression test whose original premise
    -- (a stale LIVE-vs-inert-stub command surviving deactivation) is
    -- structurally impossible now that :ProvenanceSeal is registered ONCE,
    -- unconditionally, and always queries the registry live (see init.lua).
    -- The new invariant this test documents is the locked design decision
    -- (docs/superpowers/specs/2026-07-20-nested-manifest-discovery-design.md):
    -- a session is anchored to its assignment ROOT and lives until
    -- VimLeavePre/dispose -- matching VS Code/JetBrains -- so a mere `:cd`
    -- into a directory with no manifest of its own must NOT stop, hide, or
    -- otherwise affect an already-active session elsewhere. This mirrors
    -- init_controller_spec.lua's rewritten "workspace change" test, but
    -- proves it specifically through the seal command's own behavior.
    local tmp_a = vim.fn.tempname()
    local tmp_b = vim.fn.tempname()
    vim.fn.mkdir(tmp_a, "p")
    vim.fn.mkdir(tmp_b, "p")

    local orig_cwd = vim.fn.getcwd()
    vim.cmd("cd " .. vim.fn.fnameescape(tmp_a))
    -- getcwd() may resolve symlinks (e.g. /var -> /private/var on macOS), so
    -- compare against the resolved cwd rather than the raw tempname() path.
    local resolved_a = vim.fn.getcwd()

    local seal_calls = 0
    local fake_controller = {
      seal = function()
        seal_calls = seal_calls + 1
        return {
          kind = "ok",
          bundle_path = "/tmp/hw3-bundle.zip",
          warnings = { chain_broken = false, unreadable_session = false },
        }
      end,
      stop = function() end,
    }

    handle = recorder.setup({
      -- No workspace override: resolve_and_apply falls back to
      -- vim.fn.getcwd(), so a real :cd fires DirChanged and drives a
      -- genuine re-resolve through the SAME resolve_and_apply path exercised
      -- by init_controller_spec.lua's workspace-change test. Active only for
      -- workspace A; every other cwd (workspace B) resolves inactive.
      resolve = function(start_dir)
        if start_dir == resolved_a then
          return { status = "active", root = start_dir, manifest = { assignment_id = "hw3" } }
        end
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = function()
        return fake_controller
      end,
    })

    -- Phase 1: active workspace A. :ProvenanceSeal seals it.
    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(1, seal_calls)
    assert.equals(1, #calls)
    assert.equals(vim.log.levels.INFO, calls[1].level)
    assert.is_not_nil(string.find(calls[1].message, "/tmp/hw3-bundle.zip", 1, true))

    restore()
    restore_notify = nil

    -- Phase 2: cd to workspace B, which resolves INACTIVE (no manifest of
    -- its own). A's session must stay registered and live -- :ProvenanceSeal
    -- still seals it (still exactly one active session), NOT the "not an
    -- activated assignment workspace" guidance, and NOT a no-op.
    vim.cmd("cd " .. vim.fn.fnameescape(tmp_b))

    calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(2, seal_calls) -- A was sealed AGAIN -- its session is still live
    assert.equals(1, #calls)
    assert.equals(vim.log.levels.INFO, calls[1].level)
    assert.is_not_nil(string.find(calls[1].message, "/tmp/hw3-bundle.zip", 1, true))
    assert.is_nil(string.find(calls[1].message, "not an activated assignment workspace", 1, true))

    restore()
    restore_notify = nil

    vim.cmd("cd " .. vim.fn.fnameescape(orig_cwd))
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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = make_start_recording(fake_controller),
    })

    assert.equals(2, vim.fn.exists(":ProvenanceSeal"))

    handle.dispose()
    handle = nil

    assert.equals(0, vim.fn.exists(":ProvenanceSeal"))
  end)
end)

describe("recorder.setup :ProvenanceSeal multi-session picker", function()
  local recorder

  before_each(function()
    package.loaded["provenance.recorder"] = nil
    package.loaded["provenance.recorder.init"] = nil
    recorder = require("provenance.recorder")
  end)

  local handle
  local restore_notify
  local restore_select

  after_each(function()
    if handle then
      handle.dispose()
      handle = nil
    end
    if restore_notify then
      restore_notify()
      restore_notify = nil
    end
    if restore_select then
      restore_select()
      restore_select = nil
    end
    status.detach()
  end)

  it("exactly one active session: seals it directly, no picker shown", function()
    local select_called = false
    local orig_select = vim.ui.select
    vim.ui.select = function(...)
      select_called = true
    end
    restore_select = function()
      vim.ui.select = orig_select
    end

    local seal_calls = 0
    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
        return { status = "active", root = "/tmp/cats", manifest = { assignment_id = "cats" } }
      end,
      start_recording = function()
        return {
          seal = function()
            seal_calls = seal_calls + 1
            return { kind = "ok", bundle_path = "/tmp/cats-bundle.zip", warnings = {} }
          end,
          stop = function() end,
        }
      end,
    })

    local calls, restore = capture_notify()
    restore_notify = restore

    vim.cmd("ProvenanceSeal")

    assert.equals(1, seal_calls)
    assert.is_false(select_called)
    assert.equals(vim.log.levels.INFO, calls[1].level)
  end)

  it("two active sessions: vim.ui.select is invoked with both, choosing one seals only that one", function()
    local seal_calls = { cats = 0, hog = 0 }
    local controller_cats = {
      seal = function()
        seal_calls.cats = seal_calls.cats + 1
        return { kind = "ok", bundle_path = "/tmp/cats-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }
    local controller_hog = {
      seal = function()
        seal_calls.hog = seal_calls.hog + 1
        return { kind = "ok", bundle_path = "/tmp/hog-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }

    local resolve_call_count = 0
    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
        resolve_call_count = resolve_call_count + 1
        if resolve_call_count == 1 then
          return { status = "active", root = "/tmp/cats", manifest = { assignment_id = "cats" } }
        end
        return { status = "active", root = "/tmp/hog", manifest = { assignment_id = "hog" } }
      end,
      start_recording = function(args)
        if args.workspace == "/tmp/cats" then
          return controller_cats
        end
        return controller_hog
      end,
    })

    -- Force a second resolve (a DirChanged re-fire) so the SECOND call to
    -- resolve() above registers the "hog" root too, yielding two live
    -- sessions in the registry (ensure_session is idempotent per-root, so
    -- this cleanly adds hog alongside the already-registered cats).
    vim.api.nvim_exec_autocmds("DirChanged", { group = "Provenance" })

    local selected_items
    local orig_select = vim.ui.select
    vim.ui.select = function(items, select_opts, on_choice)
      selected_items = items
      -- Choose the second item ("hog").
      on_choice(items[2].manifest.assignment_id == "hog" and items[2] or items[1])
    end
    restore_select = function()
      vim.ui.select = orig_select
    end

    vim.cmd("ProvenanceSeal")

    assert.is_not_nil(selected_items)
    assert.equals(2, #selected_items)
    assert.equals(1, seal_calls.hog)
    assert.equals(0, seal_calls.cats)
  end)

  it(":ProvenanceSeal <assignment_id> seals the named session directly, skipping the picker", function()
    local seal_calls = { cats = 0, hog = 0 }
    local controller_cats = {
      seal = function()
        seal_calls.cats = seal_calls.cats + 1
        return { kind = "ok", bundle_path = "/tmp/cats-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }
    local controller_hog = {
      seal = function()
        seal_calls.hog = seal_calls.hog + 1
        return { kind = "ok", bundle_path = "/tmp/hog-bundle.zip", warnings = {} }
      end,
      stop = function() end,
    }

    local resolve_call_count = 0
    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
        resolve_call_count = resolve_call_count + 1
        if resolve_call_count == 1 then
          return { status = "active", root = "/tmp/cats", manifest = { assignment_id = "cats" } }
        end
        return { status = "active", root = "/tmp/hog", manifest = { assignment_id = "hog" } }
      end,
      start_recording = function(args)
        if args.workspace == "/tmp/cats" then
          return controller_cats
        end
        return controller_hog
      end,
    })
    vim.api.nvim_exec_autocmds("DirChanged", { group = "Provenance" })

    local select_called = false
    local orig_select = vim.ui.select
    vim.ui.select = function(...)
      select_called = true
    end
    restore_select = function()
      vim.ui.select = orig_select
    end

    vim.cmd("ProvenanceSeal hog")

    assert.is_false(select_called)
    assert.equals(1, seal_calls.hog)
    assert.equals(0, seal_calls.cats)
  end)
end)
