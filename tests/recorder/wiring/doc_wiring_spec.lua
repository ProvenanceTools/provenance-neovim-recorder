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

--- Read the raw on-disk bytes of `path` via vim.uv (fs_open/fs_read) — NOT
--- vim.fn.readfile, which splits on "\n" and mangles CRLF/CR line endings,
--- making it useless for the exact-byte comparisons the fileformat-aware
--- content model tests below need.
local function read_raw(path)
  local uv = vim.uv or vim.loop
  local fd = assert(uv.fs_open(path, "r", 420))
  local stat = assert(uv.fs_fstat(fd))
  local data = uv.fs_read(fd, stat.size, 0)
  uv.fs_close(fd)
  return data
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
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    scratch.edit(path)

    local ev = find(events, "doc.open")
    assert.is_not_nil(ev)
    assert.equals("foo.txt", ev.data.path)
    -- fileformat=unix + endofline=true content model: matches this file's
    -- actual on-disk bytes (see doc_wiring.lua's content_bytes comment; the
    -- noeol/dos/empty variants are covered by the "fileformat-aware content
    -- model" describe block below).
    assert.equals(sha256.hex("line1\nline2\n"), ev.data.sha256)
    assert.equals(2, ev.data.line_count)
    assert.equals("line1\nline2\n", ev.data.content)
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

    -- Delta text carries a trailing "\n" per replaced-line, matching the
    -- content_bytes model (new_last > first, so non-empty replacement).
    assert.equals("edited1\n", events[2].data.deltas[1].text)
    assert.equals("edited2\n", events[3].data.deltas[1].text)
  end)

  it("REGRESSION: a single-char insert on a long line emits delta.text = just that char (not the whole line)", function()
    -- The paste-detection bug: on_lines reported each edit as a full-line
    -- replacement, so typing one char onto a >=30-char line produced a
    -- delta whose text was the whole ~30-char line. That inflated the
    -- analyzer's charsTyped (summed from delta.text.length) and tripped the
    -- >=30-char paste classifier. Precise on_bytes deltas must carry ONLY the
    -- inserted character.
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    local long = "def compute(self, a, b, c):" -- 27 chars; +1 char makes 28
    scratch.write_file(path, long .. "\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    -- Simulate an insert-mode keystroke: insert ":" at end of the long line
    -- (byte col = #long). This is the real per-keystroke shape, unlike
    -- set_lines which replaces whole lines.
    vim.api.nvim_buf_set_text(buf, 0, #long, 0, #long, { "X" })

    assert.equals(1, count(events, "doc.change"))
    local ev = find(events, "doc.change")
    assert.equals("typed", ev.data.source)
    assert.equals(1, #ev.data.deltas)
    local delta = ev.data.deltas[1]
    assert.equals("X", delta.text) -- just the char, NOT the whole line
    -- Precise empty range at the insertion point (byte==UTF-16 for ASCII).
    assert.same({ line = 0, character = #long }, delta.range.start)
    assert.same({ line = 0, character = #long }, delta.range["end"])
  end)

  it("emits an empty-text delta for a pure line deletion", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\nline3\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    -- Delete line 2 (0-indexed line 1) with no replacement lines: first=1,
    -- last=2, new_last=1 -> new_last == first, so text must be "".
    vim.api.nvim_buf_set_lines(buf, 1, 2, false, {})

    local ev = find(events, "doc.change")
    assert.is_not_nil(ev)
    assert.equals("", ev.data.deltas[1].text)
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
    assert.equals(sha256.hex("changed\n"), ev.data.sha256)
  end)

  describe("fileformat-aware content model (matches raw on-disk bytes for the analyzer's exact-hash check 8)", function()
    it("unix file with trailing newline: doc.save hash matches raw on-disk bytes (regression guard)", function()
      local workspace = scratch.workspace()
      local path = workspace .. "/unix.txt"
      scratch.write_file(path, "line1\nline2\n")

      local events, emit = new_emit()
      scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

      local buf = scratch.edit(path)
      vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed" })
      vim.cmd("write")

      local save_ev = find(events, "doc.save")
      assert.is_not_nil(save_ev)
      local raw = read_raw(path)
      assert.equals("changed\nline2\n", raw)
      -- Unchanged from the pre-fileformat-aware behavior: fileformat=unix +
      -- endofline=true is byte-identical to the old hardcoded join(...,"\n").."\n".
      assert.equals(sha256.hex(raw), save_ev.data.sha256)
    end)

    it("fileformat=dos (CRLF) file: doc.save hash matches raw CRLF on-disk bytes, delta text uses CRLF", function()
      local workspace = scratch.workspace()
      local path = workspace .. "/dos.txt"
      scratch.write_file(path, "a\r\nb\r\n")

      local events, emit = new_emit()
      scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

      local buf = scratch.edit(path)
      assert.equals("dos", vim.bo[buf].fileformat) -- Neovim auto-detects CRLF -> dos

      vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "aX" })
      vim.cmd("write")

      local raw = read_raw(path)
      assert.equals("aX\r\nb\r\n", raw)

      local save_ev = find(events, "doc.save")
      assert.is_not_nil(save_ev)
      assert.equals(sha256.hex(raw), save_ev.data.sha256)

      local change_ev = find(events, "doc.change")
      assert.is_not_nil(change_ev)
      local delta_text = change_ev.data.deltas[1].text
      assert.equals("\r\n", delta_text:sub(-2))
    end)

    it("noeol file (no trailing newline): doc.open hash matches the untouched eol-less bytes; doc.save hash matches the actually-written bytes", function()
      local workspace = scratch.workspace()
      local path = workspace .. "/noeol.txt"
      scratch.write_file(path, "abc") -- no trailing newline

      local events, emit = new_emit()
      scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

      local buf = scratch.edit(path)
      assert.is_false(vim.bo[buf].endofline)

      -- Before any write: doc.open must match the file's actual (still
      -- untouched, eol-less) on-disk bytes -- this is the case that matters
      -- if the file is submitted without ever being modified/saved.
      local open_ev = find(events, "doc.open")
      assert.is_not_nil(open_ev)
      assert.equals(sha256.hex("abc"), open_ev.data.sha256)
      assert.equals("abc", open_ev.data.content)

      -- Modify the last (only) line and save: Neovim's default 'fixeol'
      -- silently adds a trailing EOL on write even though 'endofline'
      -- itself stays reported as false -- doc.save must match what was
      -- ACTUALLY written, not the stale 'endofline' reading.
      vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "abcXYZ" })
      vim.cmd("write")

      local raw = read_raw(path)
      assert.equals("abcXYZ\n", raw) -- fixeol adds the trailing EOL back

      local save_ev = find(events, "doc.save")
      assert.is_not_nil(save_ev)
      assert.equals(sha256.hex(raw), save_ev.data.sha256)
    end)

    it("empty 0-byte file: doc.open and doc.save hashes both match empty on-disk content", function()
      local workspace = scratch.workspace()
      local path = workspace .. "/empty.txt"
      scratch.write_file(path, "")

      local events, emit = new_emit()
      scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

      scratch.edit(path)
      assert.equals("", read_raw(path))

      local open_ev = find(events, "doc.open")
      assert.is_not_nil(open_ev)
      assert.equals(sha256.hex(""), open_ev.data.sha256)
      assert.equals("", open_ev.data.content)

      vim.cmd("write")
      local raw = read_raw(path)
      assert.equals("", raw)

      local save_ev = find(events, "doc.save")
      assert.is_not_nil(save_ev)
      assert.equals(sha256.hex(raw), save_ev.data.sha256)
    end)
  end)

  it("pins the trailing-newline model: doc.open content + doc.change deltas reconstruct to doc.save's hash (analyzer offsetAt/splice)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\nline3\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    -- Replace 1 line with 2 (first=1, last=2, new_last=3): exercises the
    -- delta model where the replacement text is longer than what it
    -- replaces, and where an interior (not final) line boundary is spliced.
    vim.api.nvim_buf_set_lines(buf, 1, 2, false, { "EDITED-a", "EDITED-b" })
    vim.cmd("write")

    local open_ev = find(events, "doc.open")
    local save_ev = find(events, "doc.save")
    assert.is_not_nil(open_ev)
    assert.is_not_nil(save_ev)

    -- Minimal Lua reimplementation of the real analyzer's offsetAt/splice
    -- (packages/analysis-core/src/index/reconstruct-file.ts): a flat
    -- content string plus a line-start index, {line, character=0} only
    -- (matches what doc_wiring ever emits — character is always 0).
    local function line_starts(content)
      local starts = { 0 }
      for i = 1, #content do
        if content:sub(i, i) == "\n" then
          table.insert(starts, i)
        end
      end
      return starts
    end

    local function offset_at(content, starts, line)
      if line + 1 <= #starts then
        return starts[line + 1]
      end
      return #content
    end

    local content = open_ev.data.content
    for _, ev in ipairs(events) do
      if ev.kind == "doc.change" then
        for _, delta in ipairs(ev.data.deltas) do
          local starts = line_starts(content)
          local s = offset_at(content, starts, delta.range.start.line)
          local e = offset_at(content, starts, delta.range["end"].line)
          content = content:sub(1, s) .. delta.text .. content:sub(e + 1)
        end
      end
    end

    assert.equals("line1\nEDITED-a\nEDITED-b\nline3\n", content)
    assert.equals(sha256.hex(content), save_ev.data.sha256)
  end)

  it("precise mid-line edits (non-zero character) reconstruct via the analyzer's char-honoring splice", function()
    -- Drives real per-keystroke edits (nvim_buf_set_text) that land in the
    -- INTERIOR of a line, producing deltas with non-zero `character` columns —
    -- the shape the old line-granular path never emitted. Proves the analyzer's
    -- offsetAt(line, character) splice reconstructs them byte-for-byte. Content
    -- is ASCII, so UTF-16 character == byte column within a line.
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "abcdef\nghijkl\n")

    local events, emit = new_emit()
    scratch.handle = doc_wiring.attach({ workspace = workspace, emit = emit })

    local buf = scratch.edit(path)
    -- Insert "X" mid-line 0 at char 3: "abcdef" -> "abcXdef".
    vim.api.nvim_buf_set_text(buf, 0, 3, 0, 3, { "X" })
    -- Delete 2 chars mid-line 1 (chars 2..4): "ghijkl" -> "ghkl".
    vim.api.nvim_buf_set_text(buf, 1, 2, 1, 4, { "" })
    -- Replace 1 char with 3 mid-line 0 (char 0..1): "abcXdef" -> "ZZZbcXdef".
    vim.api.nvim_buf_set_text(buf, 0, 0, 0, 1, { "ZZZ" })
    vim.cmd("write")

    local open_ev = find(events, "doc.open")
    local save_ev = find(events, "doc.save")
    assert.is_not_nil(open_ev)
    assert.is_not_nil(save_ev)

    -- At least one emitted delta must have a non-zero character column, or this
    -- test isn't exercising what it claims to.
    local saw_nonzero_char = false
    for _, ev in ipairs(events) do
      if ev.kind == "doc.change" then
        local d = ev.data.deltas[1]
        if d.range.start.character > 0 or d.range["end"].character > 0 then
          saw_nonzero_char = true
        end
      end
    end
    assert.is_true(saw_nonzero_char)

    -- Analyzer's offsetAt(content, {line, character}) — honors BOTH line and
    -- character (ASCII: character == byte column within the line).
    local function offset_at(content, line, character)
      local cur_line, i = 0, 0
      while i < #content and cur_line < line do
        if content:sub(i + 1, i + 1) == "\n" then
          cur_line = cur_line + 1
        end
        i = i + 1
      end
      -- clamp character to the remaining line
      local j = i
      local consumed = 0
      while j < #content and content:sub(j + 1, j + 1) ~= "\n" and consumed < character do
        j = j + 1
        consumed = consumed + 1
      end
      return j
    end

    local content = open_ev.data.content
    for _, ev in ipairs(events) do
      if ev.kind == "doc.change" then
        for _, delta in ipairs(ev.data.deltas) do
          local s = offset_at(content, delta.range.start.line, delta.range.start.character)
          local e = offset_at(content, delta.range["end"].line, delta.range["end"].character)
          content = content:sub(1, s) .. delta.text .. content:sub(e + 1)
        end
      end
    end

    assert.equals("ZZZbcXdef\nghkl\n", content)
    assert.equals(sha256.hex(content), save_ev.data.sha256)
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
