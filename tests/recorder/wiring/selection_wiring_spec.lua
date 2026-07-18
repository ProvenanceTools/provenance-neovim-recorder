--- selection_wiring: CursorMoved/CursorMovedI -> selection.change, mirroring
--- VS Code's onDidChangeTextEditorSelection. Headless, REAL buffers. The
--- range-computation logic is unit-tested directly via M.compute (it needs
--- vim.str_utfindex for UTF-16 columns, so it runs in the nvim harness).
local selection_wiring = require("provenance.recorder.wiring.selection_wiring")
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")

local function new_emit()
  local events = {}
  return events, function(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
end

local function find(events, kind)
  for _, ev in ipairs(events) do
    if ev.kind == kind then
      return ev
    end
  end
  return nil
end

describe("selection_wiring.compute", function()
  local function get_line_from(lines)
    return function(row)
      return lines[row + 1] or ""
    end
  end

  it("normal mode -> empty range at cursor, was_selection=false", function()
    local res = selection_wiring.compute(
      "n",
      { row = 0, col = 2 },
      { row = 0, col = 2 },
      get_line_from({ "hello world" })
    )
    assert.is_false(res.was_selection)
    assert.same({ line = 0, character = 2 }, res.range.start)
    assert.same({ line = 0, character = 2 }, res.range["end"])
  end)

  it("insert mode is treated as a cursor point (was_selection=false)", function()
    local res = selection_wiring.compute(
      "i",
      { row = 1, col = 3 },
      { row = 1, col = 3 },
      get_line_from({ "abc", "second" })
    )
    assert.is_false(res.was_selection)
    assert.same({ line = 1, character = 3 }, res.range.start)
    assert.same({ line = 1, character = 3 }, res.range["end"])
  end)

  it("visual mode -> span from anchor to cursor (end exclusive), was_selection=true", function()
    -- "hello": anchor byte col 2 ('l'), cursor byte col 4 ('o'). Selection
    -- "llo" -> start char 2, end char 5 (exclusive of the char under cursor).
    local res = selection_wiring.compute(
      "v",
      { row = 0, col = 2 },
      { row = 0, col = 4 },
      get_line_from({ "hello world" })
    )
    assert.is_true(res.was_selection)
    assert.same({ line = 0, character = 2 }, res.range.start)
    assert.same({ line = 0, character = 5 }, res.range["end"])
  end)

  it("visual mode orders a backward selection (cursor before anchor)", function()
    local res = selection_wiring.compute(
      "v",
      { row = 0, col = 4 },
      { row = 0, col = 2 },
      get_line_from({ "hello world" })
    )
    assert.is_true(res.was_selection)
    assert.same({ line = 0, character = 2 }, res.range.start)
    assert.same({ line = 0, character = 5 }, res.range["end"])
  end)

  it("uses UTF-16 columns for the start position", function()
    -- "aa€bb": € is 3 bytes; a cursor at byte col 5 is UTF-16 col 3.
    local res = selection_wiring.compute(
      "n",
      { row = 0, col = 5 },
      { row = 0, col = 5 },
      get_line_from({ "aa\226\130\172bb" })
    )
    assert.same({ line = 0, character = 3 }, res.range.start)
  end)
end)

describe("selection_wiring.start", function()
  local scratch

  before_each(function()
    scratch = { bufs = {}, dirs = {}, doc = nil, sel = nil }
  end)

  after_each(function()
    if scratch.sel then
      scratch.sel.dispose()
    end
    if scratch.doc then
      scratch.doc.dispose()
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
  end)

  local function workspace()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    table.insert(scratch.dirs, dir)
    return dir
  end

  it("emits selection.change on cursor move in a recordable buffer", function()
    local ws = workspace()
    local path = ws .. "/foo.txt"
    local f = assert(io.open(path, "w"))
    f:write("hello world\nsecond line\n")
    f:close()

    local events, emit = new_emit()
    scratch.doc = doc_wiring.attach({ workspace = ws, emit = emit })
    scratch.sel = selection_wiring.start({ emit = emit, doc_wiring_handle = scratch.doc })

    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)

    vim.api.nvim_win_set_cursor(0, { 1, 3 })
    vim.api.nvim_exec_autocmds("CursorMoved", { buffer = buf })

    local ev = find(events, "selection.change")
    assert.is_not_nil(ev)
    assert.equals("foo.txt", ev.data.path)
    assert.is_false(ev.data.was_selection)
    assert.equals(0, ev.data.range.start.line)
    assert.equals(3, ev.data.range.start.character)
  end)

  it("does not emit for a non-recordable buffer", function()
    local ws = workspace()
    local events, emit = new_emit()
    scratch.doc = doc_wiring.attach({ workspace = ws, emit = emit })
    scratch.sel = selection_wiring.start({ emit = emit, doc_wiring_handle = scratch.doc })

    -- A scratch (nofile) buffer, never attached by doc_wiring.
    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)
    vim.api.nvim_set_current_buf(buf)
    vim.api.nvim_exec_autocmds("CursorMoved", { buffer = buf })

    assert.is_nil(find(events, "selection.change"))
  end)

  it("dispose() stops further emits and is idempotent", function()
    local ws = workspace()
    local path = ws .. "/foo.txt"
    local f = assert(io.open(path, "w"))
    f:write("hello\n")
    f:close()

    local events, emit = new_emit()
    scratch.doc = doc_wiring.attach({ workspace = ws, emit = emit })
    local sel = selection_wiring.start({ emit = emit, doc_wiring_handle = scratch.doc })

    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)

    sel.dispose()
    local before = #events
    vim.api.nvim_exec_autocmds("CursorMoved", { buffer = buf })
    assert.equals(before, #events)

    assert.has_no.errors(function()
      sel.dispose()
    end)
  end)
end)
