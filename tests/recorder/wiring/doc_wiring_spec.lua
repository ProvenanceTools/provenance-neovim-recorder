--- doc_wiring: the Neovim seam bridging buffer/autocmd signals to the pure
--- doc_events transforms. Headless, REAL buffers — no editor-API mocking,
--- since the whole point of this module is Neovim buffer/autocmd semantics.
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local sha256 = require("provenance.core.sha256")

local AUGROUP_NAME = "ProvenanceDocWiring"

--- Track everything created by a test so it can be torn down afterward:
--- buffers wiped, temp dirs deleted, handle disposed (idempotent).
local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, handle = nil }

  function scratch.workspace()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    table.insert(scratch.dirs, dir)
    return dir
  end

  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
  end

  --- Opens `path` in the current window via :edit and returns the bufnr.
  --- Tracked for wipeout in teardown().
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

describe("doc_wiring.attach", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("emits doc.open for a recordable file with correct rel/hash/lines/content", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    scratch.edit(path)

    local ev = find(events, "doc.open")
    assert.is_not_nil(ev)
    assert.equals("foo.txt", ev.data.path)
    assert.equals(sha256.hex("line1\nline2"), ev.data.sha256)
    assert.equals(2, ev.data.line_count)
    assert.equals("line1\nline2", ev.data.content)
  end)

  it("emits one doc.change per edit, source=typed, well-formed delta", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)

    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "edited1" })
    vim.api.nvim_buf_set_lines(buf, 1, 2, false, { "edited2" })

    assert.equals(2, count(events, "doc.change"))

    for _, ev in ipairs(events) do
      if ev.kind == "doc.change" then
        assert.equals("foo.txt", ev.data.path)
        assert.equals("typed", ev.data.source)
        assert.equals(1, #ev.data.deltas)
        local delta = ev.data.deltas[1]
        assert.is_number(delta.range.start.line)
        assert.is_number(delta.range["end"].line)
        assert.is_string(delta.text)
      end
    end

    assert.equals("edited1", events[2].data.deltas[1].text)
    assert.equals("edited2", events[3].data.deltas[1].text)
  end)

  it("emits doc.save with the current content hash on :write", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed" })
    vim.cmd("write")

    local ev = find(events, "doc.save")
    assert.is_not_nil(ev)
    assert.equals("foo.txt", ev.data.path)
    assert.equals(sha256.hex("changed"), ev.data.sha256)
  end)

  it("never records a file under provenance_dir (self-loop prevention)", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = provenance_dir .. "/session-x.slog"
    scratch.write_file(path, "some log content\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({
      workspace = workspace,
      provenance_dir = provenance_dir,
      emit = emit,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "more log content" })
    vim.cmd("write")

    assert.equals(0, #events)
  end)

  it("never records a file under provenance_dir created AFTER attach (realpath symmetry)", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    -- Do NOT create provenance_dir yet — attach() must exclude it from the
    -- moment it exists, not just if it already existed at attach() time.

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({
      workspace = workspace,
      provenance_dir = provenance_dir,
      emit = emit,
    })

    vim.fn.mkdir(provenance_dir, "p")
    local path = provenance_dir .. "/session-x.slog"
    scratch.write_file(path, "some log content\n")

    scratch.edit(path)

    assert.equals(0, #events)
  end)

  it("never records the .provenance-manifest file", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/.provenance-manifest"
    scratch.write_file(path, "manifest content\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    scratch.edit(path)

    assert.equals(0, #events)
  end)

  it("ignores a file outside the workspace", function()
    local workspace = scratch.workspace()
    local outside_dir = scratch.workspace() -- a second, unrelated temp dir
    local path = outside_dir .. "/bar.txt"
    scratch.write_file(path, "outside content\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    scratch.edit(path)

    assert.equals(0, #events)
  end)

  it("ignores a non-file buffer (buftype=nofile)", function()
    local workspace = scratch.workspace()

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)
    vim.api.nvim_buf_set_name(buf, workspace .. "/scratch.txt")
    vim.api.nvim_set_option_value("buftype", "nofile", { buf = buf })

    -- Drive the same code path a real nofile buffer would hit.
    vim.api.nvim_exec_autocmds("BufReadPost", { buffer = buf })
    vim.api.nvim_exec_autocmds("BufNewFile", { buffer = buf })

    assert.equals(0, #events)
  end)

  it("emits a synthetic doc.open for an already-open buffer (catch-up)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/already-open.txt"
    scratch.write_file(path, "pre-existing content\n")

    -- Open BEFORE attach() — no wiring registered yet, so no live event.
    scratch.edit(path)

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local ev = find(events, "doc.open")
    assert.is_not_nil(ev)
    assert.equals("already-open.txt", ev.data.path)
  end)

  it("does not double-emit doc.open for the same buffer (de-dup)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "content\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    scratch.edit(path)
    -- Force a re-read of the same buffer/file (re-fires BufReadPost).
    vim.cmd("edit!")

    assert.equals(1, count(events, "doc.open"))
  end)

  it("emits doc.close exactly once per close (BufDelete + BufUnload both fire)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "content\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    vim.cmd("bwipeout! " .. buf)

    assert.equals(1, count(events, "doc.close"))
    local ev = find(events, "doc.close")
    assert.equals("foo.txt", ev.data.path)
  end)

  it("dispose() removes the augroup and no further events emit", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "content\n")

    local events, emit = new_emit()
    local handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    local before = #events
    assert.is_true(before > 0)

    handle.dispose()
    scratch.handle = nil -- already disposed; don't double-dispose in teardown

    local ok, autocmds = pcall(vim.api.nvim_get_autocmds, { group = AUGROUP_NAME })
    assert.is_true(not ok or #autocmds == 0)

    -- Further edits/saves must not emit anything new.
    if vim.api.nvim_buf_is_valid(buf) then
      pcall(vim.api.nvim_buf_set_lines, buf, 0, 1, false, { "after dispose" })
    end
    assert.equals(before, #events)

    -- dispose() is idempotent.
    assert.has_no.errors(function()
      handle.dispose()
    end)
  end)
end)
