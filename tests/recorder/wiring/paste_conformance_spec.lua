--- Payload-shape conformance for the three-signal paste assembly (Plan 6,
--- Task 6), mirroring provjet's payload-conformance discipline: assert the
--- emitted `paste`, `doc.change`, and `paste.anomaly` event `data` shapes
--- match log-core's events.ts EXACTLY (field names + optionality), field by
--- field — not merely "the recorder didn't crash".
---
--- Reference (read at implementation time):
--- packages/log-core/src/events.ts —
---   PastePayload = { path: string; range: Range; length: number;
---     sha256: string; content?: string; content_head?: string;
---     content_tail?: string }
---   DocChangePayload = { path: string; deltas: Array<DocChangeDelta>;
---     source: 'typed' | 'paste_likely' | 'paste_confirmed' }
---   PasteAnomalyPayload = { intercepted_count: number;
---     large_insert_count: number }
---
--- Events are generated via the REAL assembly (doc_wiring + paste_assembly),
--- exercising the actual production code path, then their captured `data`
--- tables are checked against the allowed field sets above. See
--- paste_assembly_spec.lua's module header for why the `paste` kind test
--- drives the empty-range shape via a real insert-only buffer mutation
--- rather than relying on vim.paste's own (always non-empty-range) charwise
--- put.
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local paste_assembly = require("provenance.recorder.wiring.paste_assembly")

--- See paste_assembly_spec.lua's `install_local_clipboard` for why: Plenary's
--- directory runner spawns one real `nvim --headless` subprocess per spec
--- file, concurrently, and on macOS the "+`/`"*` registers are backed by the
--- real, process-shared OS pasteboard -- racy against any other concurrently
--- running spec file that also touches them (this repo's pre-existing
--- paste_intercept_spec.lua does). Redirect "+`/`"*` storage onto a private
--- in-process table instead, so this file's register writes/reads never
--- race another file's.
local function install_local_clipboard()
  local store = { ["+"] = { {}, "v" }, ["*"] = { {}, "v" } }
  vim.g.clipboard = {
    name = "ProvenanceTestLocalClipboard",
    copy = {
      ["+"] = function(lines, regtype)
        store["+"] = { lines, regtype }
      end,
      ["*"] = function(lines, regtype)
        store["*"] = { lines, regtype }
      end,
    },
    paste = {
      ["+"] = function()
        return store["+"]
      end,
      ["*"] = function()
        return store["*"]
      end,
    },
  }
end

local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, doc_handle = nil, assembly_handle = nil }

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

  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  function scratch.scratch_buf()
    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)
    return buf
  end

  function scratch.teardown()
    if scratch.assembly_handle then
      scratch.assembly_handle.dispose()
    end
    if scratch.doc_handle then
      scratch.doc_handle.dispose()
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
    pcall(vim.fn.setreg, "+", "")
    pcall(vim.fn.setreg, "*", "")
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

--- Asserts `data`'s key set is exactly `allowed` (a set of key -> true).
local function assert_key_set(data, allowed, label)
  for k in pairs(data) do
    assert.is_true(allowed[k] ~= nil, label .. ": unexpected field " .. tostring(k))
  end
end

local HEX64 = "^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$"

describe("paste assembly: payload-shape conformance (log-core events.ts)", function()
  local scratch

  before_each(function()
    install_local_clipboard()
    scratch = new_scratch()
    vim.fn.setreg("+", "")
    vim.fn.setreg("*", "")
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("`paste` event data matches PastePayload: path, range{start,end{line,character}}, length, sha256(64-hex), and exactly one of content OR (content_head+content_tail)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    scratch.assembly_handle = paste_assembly.attach({ emit = emit, doc_wiring_handle = scratch.doc_handle })

    local buf = scratch.edit(path)
    local clip = string.rep("p", 32)

    local decoy = scratch.scratch_buf()
    vim.api.nvim_set_current_buf(decoy)
    vim.fn.setreg("+", clip)
    vim.paste({ clip }, -1)

    vim.api.nvim_set_current_buf(buf)
    vim.api.nvim_buf_set_lines(buf, 0, 0, false, { clip })

    local ev = find(events, "paste")
    assert.is_not_nil(ev)
    local data = ev.data

    local allowed = {
      path = true,
      range = true,
      length = true,
      sha256 = true,
      content = true,
      content_head = true,
      content_tail = true,
    }
    assert_key_set(data, allowed, "PastePayload")

    assert.is_string(data.path)

    assert.is_table(data.range)
    assert.is_table(data.range.start)
    assert.is_number(data.range.start.line)
    assert.is_number(data.range.start.character)
    assert.is_table(data.range["end"])
    assert.is_number(data.range["end"].line)
    assert.is_number(data.range["end"].character)

    assert.is_number(data.length)

    assert.is_string(data.sha256)
    assert.equals(64, #data.sha256)
    assert.is_not_nil(data.sha256:match(HEX64))

    -- Exactly one of content OR (content_head AND content_tail), never both,
    -- never neither.
    local has_content = data.content ~= nil
    local has_head = data.content_head ~= nil
    local has_tail = data.content_tail ~= nil
    assert.equals(has_head, has_tail) -- head/tail always paired
    assert.is_true(has_content ~= has_head) -- XOR: exactly one branch present
    if has_content then
      assert.is_string(data.content)
    else
      assert.is_string(data.content_head)
      assert.is_string(data.content_tail)
    end
  end)

  it("`doc.change` event data matches DocChangePayload: path, deltas(array), source in {typed,paste_likely,paste_confirmed}", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    scratch.assembly_handle = paste_assembly.attach({ emit = emit, doc_wiring_handle = scratch.doc_handle })

    local buf = scratch.edit(path)

    -- typed
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "hi" })
    -- paste_likely
    vim.api.nvim_buf_set_lines(buf, 1, 2, false, {
      string.rep("a", 15),
      string.rep("b", 15),
      string.rep("c", 15),
    })

    local allowed = { path = true, deltas = true, source = true }
    local source_enum = { typed = true, paste_likely = true, paste_confirmed = true }

    local seen_sources = {}
    for _, ev in ipairs(events) do
      if ev.kind == "doc.change" then
        local data = ev.data
        assert_key_set(data, allowed, "DocChangePayload")
        assert.is_string(data.path)
        assert.is_table(data.deltas)
        assert.is_true(source_enum[data.source] ~= nil, "unexpected source: " .. tostring(data.source))
        seen_sources[data.source] = true

        for _, delta in ipairs(data.deltas) do
          assert.is_table(delta.range)
          assert.is_string(delta.text)
        end
      end
    end

    assert.is_true(seen_sources["typed"])
    assert.is_true(seen_sources["paste_likely"])
  end)

  it("`paste.anomaly` event data matches PasteAnomalyPayload EXACTLY: {intercepted_count:number, large_insert_count:number}, no other fields", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
      interval_ms = 20,
      tolerance = 0,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, {
      string.rep("a", 15),
      string.rep("b", 15),
      string.rep("c", 15),
    })

    local ok = vim.wait(500, function()
      return find(events, "paste.anomaly") ~= nil
    end, 10)
    assert.is_true(ok)

    local ev = find(events, "paste.anomaly")
    local data = ev.data

    local allowed = { intercepted_count = true, large_insert_count = true }
    assert_key_set(data, allowed, "PasteAnomalyPayload")

    local n = 0
    for _ in pairs(data) do
      n = n + 1
    end
    assert.equals(2, n)

    assert.is_number(data.intercepted_count)
    assert.is_number(data.large_insert_count)
  end)
end)
