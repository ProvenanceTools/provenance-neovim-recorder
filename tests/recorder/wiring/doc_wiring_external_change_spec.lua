--- doc_wiring <-> external_change_coordinator integration (Plan 9): the
--- OPTIONAL `opts.external_change` seam threading the coordinator's hooks
--- into doc.open/doc.change/BufWritePost, plus the noeol reconcile-before-
--- check fix (a Plan 5 carry-forward). Headless, real buffers, real
--- coordinator (unless a test needs to assert hook call order, where a
--- capturing fake stands in). Mirrors doc_wiring_spec.lua's scratch harness.
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local coordinator_mod = require("provenance.recorder.watch.external_change_coordinator")

local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, handle = nil, coordinator = nil }

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

  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  function scratch.teardown()
    if scratch.handle then
      scratch.handle.dispose()
    end
    if scratch.coordinator then
      scratch.coordinator.dispose()
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

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

local function find(events, kind)
  for _, ev in ipairs(events) do
    if ev.kind == kind then
      return ev
    end
  end
  return nil
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

describe("doc_wiring <-> external_change_coordinator integration", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
    vim.o.autoread = false
  end)

  it("seed_open on open: the coordinator's registry has an ExpectedContent for rel after doc.open", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.coordinator = coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "foo.txt" },
      emit = emit,
    })

    scratch.handle = doc_wiring.attach({
      workspace = workspace,
      emit = emit,
      external_change = scratch.coordinator,
    })

    scratch.edit(path)

    assert.is_not_nil(find(events, "doc.open"))
    local ec = scratch.coordinator.registry.get("foo.txt")
    assert.is_not_nil(ec)
    assert.equals("line1\nline2\n", ec.get_content())
  end)

  it("apply_change on edit: the coordinator's ExpectedContent tracks the edit", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.coordinator = coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "foo.txt" },
      emit = emit,
    })

    scratch.handle = doc_wiring.attach({
      workspace = workspace,
      emit = emit,
      external_change = scratch.coordinator,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "edited1" })

    local ec = scratch.coordinator.registry.get("foo.txt")
    assert.is_not_nil(ec)
    assert.equals("edited1\nline2\n", ec.get_content())
  end)

  it("clean save: :write emits doc.save and NO fs.external_change", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.coordinator = coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "foo.txt" },
      emit = emit,
    })

    scratch.handle = doc_wiring.attach({
      workspace = workspace,
      emit = emit,
      external_change = scratch.coordinator,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed" })
    vim.cmd("write")

    assert.is_not_nil(find(events, "doc.save"))
    assert.equals(0, count(events, "fs.external_change"))
  end)

  it("hook order on save: reconcile_save -> note_save -> check_after_save -> doc.save emit", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\n")

    local events, emit = new_emit()
    local calls = {}
    local fake_ec_deps = {
      seed_open = function() end,
      apply_change = function() end,
      reconcile_save = function()
        table.insert(calls, "reconcile_save")
      end,
      note_save = function()
        table.insert(calls, "note_save")
      end,
      check_after_save = function()
        table.insert(calls, "check_after_save")
      end,
    }

    local wrapped_emit = function(kind, data)
      if kind == "doc.save" then
        table.insert(calls, "emit:doc.save")
      end
      emit(kind, data)
    end

    scratch.handle = doc_wiring.attach({
      workspace = workspace,
      emit = wrapped_emit,
      external_change = fake_ec_deps,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed" })
    vim.cmd("write")

    assert.same({ "reconcile_save", "note_save", "check_after_save", "emit:doc.save" }, calls)
  end)

  it(
    "NOEOL FIX regression: editing above the last line of a noeol file, then :write (fixeol adds a trailing "
      .. "newline), does NOT emit fs.external_change for the resulting clean save",
    function()
      local workspace = scratch.workspace()
      local path = workspace .. "/noeol.txt"
      scratch.write_file(path, "a\nb\nc") -- 3 lines, no trailing newline

      local events, emit = new_emit()
      scratch.coordinator = coordinator_mod.start({
        workspace = workspace,
        files_under_review = { "noeol.txt" },
        emit = emit,
      })

      scratch.handle = doc_wiring.attach({
        workspace = workspace,
        emit = emit,
        external_change = scratch.coordinator,
      })

      local buf = scratch.edit(path)
      assert.is_false(vim.bo[buf].endofline)

      -- Edit line 0 ("a" -> "aa"), WITHOUT touching the last line ("c") —
      -- isolates the fix from the already-covered "edit the last line"
      -- doc_wiring_spec.lua case.
      vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "aa" })
      vim.cmd("write")

      -- Sanity: fixeol did add the trailing newline on disk, so this test
      -- actually exercises the divergence the fix addresses.
      local uv = vim.uv or vim.loop
      local fd = assert(uv.fs_open(path, "r", 420))
      local stat = assert(uv.fs_fstat(fd))
      local raw = uv.fs_read(fd, stat.size, 0)
      uv.fs_close(fd)
      assert.equals("aa\nb\nc\n", raw)

      assert.is_not_nil(find(events, "doc.save"))
      assert.equals(
        0,
        count(events, "fs.external_change"),
        "the editor's own fixeol-added trailing newline must not be misread as an external change"
      )
    end
  )

  it("unchanged when external_change is nil: doc.open/change/save emit exactly as before", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed" })
    vim.cmd("write")

    assert.equals(1, count(events, "doc.open"))
    assert.equals(1, count(events, "doc.change"))
    assert.equals(1, count(events, "doc.save"))
    assert.equals(0, count(events, "fs.external_change"))
  end)
end)
