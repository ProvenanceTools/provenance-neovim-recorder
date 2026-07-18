--- Tests for external_change_coordinator (Plan 5, Task 8 — the coordinator
--- that ties Paths 1-3 together behind one shared registry/recent_saves and
--- one dispose). Headless, real vim.uv file I/O + real buffers against a
--- temp workspace dir; a fake `emit` capturing {kind, data}; a controllable
--- clock.
local coordinator_mod = require("provenance.recorder.watch.external_change_coordinator")
local sha256 = require("provenance.core.sha256")

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

--- Track everything created by a test so it can be torn down afterward:
--- coordinator handles disposed, buffers wiped, temp dirs deleted. Mirrors
--- reload_checker_spec.lua's new_scratch.
local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, handles = {} }

  function scratch.workspace()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    table.insert(scratch.dirs, dir)
    return dir
  end

  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local uv = vim.uv or vim.loop
    local fd = assert(uv.fs_open(path, "w", 420))
    if #content > 0 then
      assert(uv.fs_write(fd, content))
    end
    assert(uv.fs_close(fd))
  end

  --- Opens `path` in the current window via :edit and returns the bufnr.
  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  function scratch.track(handle)
    table.insert(scratch.handles, handle)
    return handle
  end

  function scratch.teardown()
    for _, handle in ipairs(scratch.handles) do
      pcall(handle.dispose)
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
  end

  return scratch
end

describe("external_change_coordinator", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
    vim.o.autoread = false
  end)

  it("PATH 1 alone: save-time check emits ONE external_change and resets the shared registry", function()
    local workspace = scratch.workspace()
    local abs_path = workspace .. "/a.py"
    local original = "print('hello')\n"
    scratch.write_file(abs_path, original)

    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "a.py" },
      emit = emit,
      get_now = function() return 0 end,
    }))

    coordinator.seed_open("a.py", original)

    local disk_content = "print('overwritten externally')\n"
    scratch.write_file(abs_path, disk_content)

    coordinator.check_after_save("a.py", abs_path)

    assert.equals(1, #events)
    local ev = events[1]
    assert.equals("fs.external_change", ev.kind)
    assert.equals("a.py", ev.data.path)
    assert.equals("modify", ev.data.operation)
    assert.equals(sha256.hex(original), ev.data.old_hash)
    assert.equals(sha256.hex(disk_content), ev.data.new_hash)

    local ec = coordinator.registry.get("a.py")
    assert.equals(disk_content, ec.get_content())
    assert.equals(sha256.hex(disk_content), ec.hash())
  end)

  it("NO DOUBLE-EMIT: Path 1 and Path 2 observing the same save emit exactly ONE event total", function()
    local workspace = scratch.workspace()
    local abs_path = workspace .. "/a.py"
    local original = "before\n"
    scratch.write_file(abs_path, original)

    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "a.py" },
      emit = emit,
      get_now = function() return 0 end,
      tolerance_ms = 250,
    }))

    coordinator.seed_open("a.py", original)

    -- doc-wiring's real ordering: note_save BEFORE the on-disk write is
    -- observed/checked.
    coordinator.note_save("a.py")

    local disk_content = "after\n"
    scratch.write_file(abs_path, disk_content)

    -- Path 1 fires first (BufWritePost order) and claims the event.
    coordinator.check_after_save("a.py", abs_path)
    assert.equals(1, #events)

    -- Path 2 firing for the SAME write (simulated directly via the exposed
    -- test-only watcher seam): must emit NOTHING — suppressed by BOTH the
    -- recent_saves tolerance window AND the fact that Path 1 already reset
    -- the model to disk reality (clean_save either way).
    coordinator._watcher.handle_path_event("a.py", abs_path)

    assert.equals(1, #events, "total emits across both paths must be exactly one")
  end)

  it("no double-emit when Path 2 fires AFTER the tolerance window (mechanism 2 / reset alone)", function()
    local workspace = scratch.workspace()
    local abs_path = workspace .. "/a.py"
    local original = "before\n"
    scratch.write_file(abs_path, original)

    local now = 0
    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "a.py" },
      emit = emit,
      get_now = function() return now end,
      -- default tolerance_ms (250) — deliberately not overridden, so this
      -- test exercises the realistic default relationship where
      -- poll_interval_ms (1000) > tolerance_ms.
    }))

    coordinator.seed_open("a.py", original)

    -- note_save at now=0, mirroring doc-wiring's real ordering (note_save
    -- BEFORE the on-disk write is observed/checked).
    coordinator.note_save("a.py")

    local disk_content = "after\n"
    scratch.write_file(abs_path, disk_content)

    -- Path 1 fires first (BufWritePost order): claims the event AND resets
    -- the shared ExpectedContent to disk_content.
    coordinator.check_after_save("a.py", abs_path)
    assert.equals(1, #events)

    -- Advance the clock PAST the tolerance window (250ms). recent_saves'
    -- tolerance (mechanism 1) is now EXPIRED — it can no longer suppress
    -- Path 2. If mechanism 2 (ec.reset after emit) were absent, Path 2
    -- firing for the SAME unchanged-since disk content would double-emit.
    now = 251

    -- Path 2 fires for the SAME disk write (the file on disk is still
    -- disk_content — no new external change happened). Reached the same way
    -- the "NO DOUBLE-EMIT" test above reaches Path 2: the exposed test-only
    -- watcher seam.
    coordinator._watcher.handle_path_event("a.py", abs_path)

    -- Still exactly one event: with the tolerance window expired, ONLY the
    -- reset (Path 1 having already updated the shared ExpectedContent to
    -- disk_content) makes Path 2's compare_saved_content see a clean_save
    -- (disk == expected) and emit nothing.
    assert.equals(1, #events, "mechanism 2 (ec.reset) alone must suppress Path 2 past the tolerance window")
  end)

  it("PATH 3 alone: reload-from-disk emits ONE external_change", function()
    local workspace = scratch.workspace()
    local abs_path = workspace .. "/b.py"
    local original = "print('hello')\n"
    scratch.write_file(abs_path, original)

    local buf = scratch.edit(abs_path)

    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "b.py" },
      emit = emit,
      get_now = function() return 0 end,
    }))

    coordinator.seed_open("b.py", original)

    local disk_content = "print('overwritten externally')\n"
    scratch.write_file(abs_path, disk_content)

    coordinator.on_file_changed_shell(buf)

    assert.equals(1, #events)
    local ev = events[1]
    assert.equals("fs.external_change", ev.kind)
    assert.equals("b.py", ev.data.path)
    assert.equals("modify", ev.data.operation)
    assert.equals(sha256.hex(original), ev.data.old_hash)
    assert.equals(sha256.hex(disk_content), ev.data.new_hash)
  end)

  it("note_save tolerance boundary: within tolerance_ms Path 2 is suppressed; past it, Path 2 emits", function()
    local workspace = scratch.workspace()
    local abs_path = workspace .. "/a.py"
    local original = "before\n"
    scratch.write_file(abs_path, original)

    local now = 0
    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "a.py" },
      emit = emit,
      get_now = function() return now end,
      tolerance_ms = 250,
    }))

    coordinator.seed_open("a.py", original)

    now = 1000
    coordinator.note_save("a.py")

    local disk_content = "after\n"
    scratch.write_file(abs_path, disk_content)

    -- Immediately after note_save (well within the 250ms window): suppressed.
    now = 1100
    coordinator._watcher.handle_path_event("a.py", abs_path)
    assert.equals(0, #events)

    -- Past the tolerance window: the SAME on-disk change is now reported.
    now = 1300
    coordinator._watcher.handle_path_event("a.py", abs_path)
    assert.equals(1, #events)
    assert.equals("modify", events[1].data.operation)
  end)

  describe("dispose", function()
    it("is idempotent and stops all three paths: no path emits afterward", function()
      local workspace = scratch.workspace()
      local abs_path = workspace .. "/a.py"
      local original = "before\n"
      scratch.write_file(abs_path, original)

      local buf = scratch.edit(abs_path)

      local events, emit = new_emit()
      local coordinator = coordinator_mod.start({
        workspace = workspace,
        files_under_review = { "a.py" },
        emit = emit,
        get_now = function() return 0 end,
      })

      coordinator.seed_open("a.py", original)

      assert.has_no.errors(function() coordinator.dispose() end)
      assert.has_no.errors(function() coordinator.dispose() end)

      local disk_content = "after dispose\n"
      scratch.write_file(abs_path, disk_content)

      -- Path 1
      coordinator.check_after_save("a.py", abs_path)
      -- Path 3
      coordinator.on_file_changed_shell(buf)
      -- Path 2: the REAL poll-driven watcher was stopped by dispose(), so no
      -- external write after this point can reach handle_path_event via the
      -- production callback path. (handle_path_event itself remains a
      -- callable pure decision function post-dispose by design — see
      -- fs_watcher.lua's own docstring; it is not itself dispose-gated,
      -- because nothing but the now-stopped poll callback invokes it in
      -- production.)
      vim.wait(200)

      assert.equals(0, #events)
    end)

    it("removes the ProvenanceExternalChange augroup", function()
      local workspace = scratch.workspace()
      local events, emit = new_emit()
      local coordinator = coordinator_mod.start({
        workspace = workspace,
        files_under_review = {},
        emit = emit,
      })

      -- Augroup exists while active.
      assert.has_no.errors(function()
        vim.api.nvim_get_autocmds({ group = "ProvenanceExternalChange" })
      end)

      coordinator.dispose()

      assert.has_error(function()
        vim.api.nvim_get_autocmds({ group = "ProvenanceExternalChange" })
      end)
    end)

    it("safe with zero watched files", function()
      local workspace = scratch.workspace()
      local events, emit = new_emit()
      local coordinator = coordinator_mod.start({
        workspace = workspace,
        files_under_review = {},
        emit = emit,
      })

      assert.has_no.errors(function() coordinator.dispose() end)
    end)
  end)

  it("apply_change updates the shared ExpectedContent for a tracked path", function()
    local workspace = scratch.workspace()
    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "a.py" },
      emit = emit,
    }))

    coordinator.seed_open("a.py", "hello\n")
    coordinator.apply_change("a.py", {
      {
        range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 5 } },
        text = "goodbye",
      },
    })

    local ec = coordinator.registry.get("a.py")
    assert.equals("goodbye\n", ec.get_content())
  end)

  it("apply_change on an untracked path is a no-op (no error)", function()
    local workspace = scratch.workspace()
    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = {},
      emit = emit,
    }))

    assert.has_no.errors(function()
      coordinator.apply_change("never.py", { { range = { start = { line = 0, character = 0 }, ["end"] = { line = 0, character = 0 } }, text = "x" } })
    end)
  end)

  it("INTEGRATION: autoread + :checktime drives Path 3 through the real FileChangedShellPost autocmd", function()
    local workspace = scratch.workspace()
    local abs_path = workspace .. "/a.py"
    local original = "print('hello')\n"
    scratch.write_file(abs_path, original)

    local buf = scratch.edit(abs_path)

    local events, emit = new_emit()
    local coordinator = scratch.track(coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "a.py" },
      emit = emit,
      get_now = function() return 0 end,
    }))

    coordinator.seed_open("a.py", original)

    local disk_content = "print('changed on disk externally')\n"
    scratch.write_file(abs_path, disk_content)

    vim.bo[buf].autoread = true
    vim.o.autoread = true
    vim.cmd("checktime")

    assert.equals(1, #events)
    local ev = events[1]
    assert.equals("fs.external_change", ev.kind)
    assert.equals("a.py", ev.data.path)
    assert.equals("modify", ev.data.operation)
  end)
end)
