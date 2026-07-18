--- Controller lifecycle wiring (Plan 9): recorder.setup() starts a live
--- recording_controller on genuine activation and stops it on
--- deactivation/dispose/workspace-change. init_spec.lua only exercises the
--- fake-loader SKIP path (should_start_recording gated off); this spec drives
--- the INJECTABLE opts.start_recording seam so the controller-lifecycle
--- branch (should_start_recording true, controller_workspace guard,
--- stop_controller()) runs for real without starting an actual recording
--- session. Mirrors init_spec.lua's harness style (fresh require per test,
--- after_each dispose, status.detach() belt-and-suspenders).
local status = require("provenance.recorder.status")

--- Builds a fake controller + capturing start_recording seam.
--- @return function start_recording, table calls (list of args tables), function stop_calls_for(controller) -- not needed; each fake controller tracks its own stop calls
local function make_start_recording_spy()
  local calls = {}

  local function start_recording(args)
    local fake_controller = {
      stop_calls = {},
    }
    function fake_controller.stop(reason)
      table.insert(fake_controller.stop_calls, reason)
    end

    table.insert(calls, { args = args, controller = fake_controller })
    return fake_controller
  end

  return start_recording, calls
end

describe("recorder.setup controller lifecycle", function()
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
    status.detach()
  end)

  it("active loader + injected start_recording: controller is started once with the resolved workspace/manifest", function()
    local start_recording, calls = make_start_recording_spy()
    local manifest = { assignment_id = "hw3" }

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = manifest }
      end,
      start_recording = start_recording,
    })

    assert.equals(1, #calls)
    assert.equals("/tmp/ws-a", calls[1].args.workspace)
    assert.equals(manifest, calls[1].args.manifest)
    assert.equals("/tmp/ws-a/.provenance", calls[1].args.provenance_dir)
  end)

  it("dispose(): stops the live controller", function()
    local start_recording, calls = make_start_recording_spy()

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = start_recording,
    })

    assert.equals(1, #calls)
    local fake_controller = calls[1].controller
    assert.equals(0, #fake_controller.stop_calls)

    handle.dispose()
    handle = nil

    assert.equals(1, #fake_controller.stop_calls)

    -- Belt-and-suspenders: augroup is also gone (existing assertion style).
    local ok, result = pcall(vim.api.nvim_get_autocmds, { group = "Provenance" })
    if ok then
      assert.equals(0, #result)
    else
      assert.is_true(true)
    end
  end)

  it("inactive loader: start_recording is never called", function()
    local start_recording, calls = make_start_recording_spy()

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "inactive", reason = "no_manifest_file" }
      end,
      start_recording = start_recording,
    })

    assert.equals(0, #calls)
    -- The inert seal stub path is unchanged.
    assert.equals(2, vim.fn.exists(":ProvenanceSeal"))
  end)

  it("re-firing activation for the SAME workspace does not double-start the controller", function()
    local start_recording, calls = make_start_recording_spy()

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      load_and_verify = function()
        return { status = "active", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = start_recording,
    })

    assert.equals(1, #calls)
    local first_controller = calls[1].controller

    -- Simulate the same VimEnter/DirChanged autocmd firing again for the
    -- same (still-active) workspace, exactly as a redundant DirChanged would
    -- in real Neovim use (e.g. re-`:cd`-ing into the same directory).
    vim.api.nvim_exec_autocmds("DirChanged", { group = "Provenance" })

    assert.equals(1, #calls)
    assert.equals(0, #first_controller.stop_calls)
  end)

  it("workspace change: stops the old controller and starts a new one for the new workspace", function()
    local start_recording, calls = make_start_recording_spy()

    local tmp_a = vim.fn.tempname()
    local tmp_b = vim.fn.tempname()
    vim.fn.mkdir(tmp_a, "p")
    vim.fn.mkdir(tmp_b, "p")

    local orig_cwd = vim.fn.getcwd()
    vim.cmd("cd " .. vim.fn.fnameescape(tmp_a))
    -- getcwd() may resolve symlinks (e.g. /var -> /private/var on macOS), so
    -- compare against the resolved cwd rather than the raw tempname() path.
    local resolved_a = vim.fn.getcwd()

    handle = recorder.setup({
      -- No workspace override: resolve_and_apply falls back to
      -- vim.fn.getcwd(), so a real :cd triggers a genuine workspace change.
      load_and_verify = function(workspace)
        return { status = "active", manifest = { assignment_id = "hw3", workspace = workspace } }
      end,
      start_recording = start_recording,
    })

    assert.equals(1, #calls)
    assert.equals(resolved_a, calls[1].args.workspace)
    local controller_a = calls[1].controller
    assert.equals(0, #controller_a.stop_calls)

    vim.cmd("cd " .. vim.fn.fnameescape(tmp_b))
    local resolved_b = vim.fn.getcwd()

    assert.equals(2, #calls)
    assert.equals(resolved_b, calls[2].args.workspace)
    assert.equals(1, #controller_a.stop_calls)

    vim.cmd("cd " .. vim.fn.fnameescape(orig_cwd))
  end)
end)
