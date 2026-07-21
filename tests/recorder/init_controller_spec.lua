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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = manifest }
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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
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

  it("VimLeavePre: stops the live controller so session.end is emitted before Neovim exits", function()
    -- Regression: without a VimLeavePre teardown, a normal :q never calls
    -- session.stop(), so session.end is never written and the session is left
    -- "open" on disk. Two such never-closed sessions in one workspace's
    -- .provenance/ read to the analyzer as impossible overlapping sessions
    -- (an open range always overlaps a later one), falsely tripping its
    -- clock-manipulation heuristic even though the student did nothing wrong.
    local start_recording, calls = make_start_recording_spy()

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
      end,
      start_recording = start_recording,
    })

    assert.equals(1, #calls)
    local fake_controller = calls[1].controller
    assert.equals(0, #fake_controller.stop_calls)

    -- Fire VimLeavePre exactly as Neovim would on quit.
    vim.api.nvim_exec_autocmds("VimLeavePre", { group = "Provenance" })

    assert.equals(1, #fake_controller.stop_calls)

    -- Idempotent: a subsequent dispose() (after_each) must not double-stop the
    -- already-stopped controller into a second session.end.
    handle.dispose()
    handle = nil
    assert.equals(1, #fake_controller.stop_calls)
  end)

  it("inactive loader: start_recording is never called", function()
    local start_recording, calls = make_start_recording_spy()

    handle = recorder.setup({
      workspace = "/tmp/ws-a",
      resolve = function()
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
      resolve = function()
        return { status = "active", root = "/tmp/ws-a", manifest = { assignment_id = "hw3" } }
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

  it("workspace change: the OLD session keeps running (registry parity, locked design) AND a new session starts for the new cwd", function()
    -- Locked design decision (docs/superpowers/specs/2026-07-20-nested-manifest-discovery-design.md):
    -- a session is anchored to its assignment ROOT and lives until
    -- VimLeavePre/dispose, matching VS Code/JetBrains (session lifetime is
    -- the editor process, not the active folder/cwd) -- this is required so
    -- a student who keeps editing assignment A's buffers after `:cd`-ing
    -- elsewhere is still recorded. cwd is only ever a FALLBACK anchor
    -- (BufEnter/BufReadPost/BufNewFile is primary); a mere `:cd` must never
    -- stop a still-live session for a DIFFERENT root. Privacy is unaffected:
    -- session A only ever records files under A's own root regardless of
    -- what cwd currently is.
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
      -- vim.fn.getcwd(), so a real :cd triggers a genuine cwd re-resolve.
      resolve = function(start_dir)
        return { status = "active", root = start_dir, manifest = { assignment_id = "hw3", workspace = start_dir } }
      end,
      start_recording = start_recording,
    })

    assert.equals(1, #calls)
    assert.equals(resolved_a, calls[1].args.workspace)
    local controller_a = calls[1].controller
    assert.equals(0, #controller_a.stop_calls)

    vim.cmd("cd " .. vim.fn.fnameescape(tmp_b))
    local resolved_b = vim.fn.getcwd()

    -- A new session for B is started...
    assert.equals(2, #calls)
    assert.equals(resolved_b, calls[2].args.workspace)
    local controller_b = calls[2].controller

    -- ...and A's session is NOT stopped just because cwd moved away from it.
    assert.equals(0, #controller_a.stop_calls)
    assert.equals(0, #controller_b.stop_calls)

    -- Both remain live until VimLeavePre/dispose stops every session.
    vim.api.nvim_exec_autocmds("VimLeavePre", { group = "Provenance" })
    assert.equals(1, #controller_a.stop_calls)
    assert.equals(1, #controller_b.stop_calls)

    vim.cmd("cd " .. vim.fn.fnameescape(orig_cwd))
  end)
end)
