--- Save-time race regression pins (recorder PRD §4.5).
---
--- The VS Code and JetBrains recorders both compared a disk snapshot taken at
--- save time against a LIVE, mutating expected-content model, across an async
--- boundary (`readFile().then(...)` / a pooled-thread hop). A keystroke landing
--- in that window made the model disagree with the disk, so the recorder
--- emitted a bogus `fs.external_change` for the student's own save — and then
--- `reset()` rolled the model BACKWARDS onto the stale snapshot, guaranteeing
--- the next save mismatched too. A 156-submission VS Code corpus carries 3316
--- such false events.
---
--- This recorder is immune, and is the reference implementation, for two
--- reasons that these tests exist to PIN:
---
---   1. `reconcile_save(rel, written)` anchors the model to the bytes Neovim
---      ACTUALLY wrote, BEFORE anything is compared. The comparison is then
---      "what we wrote" vs "what is on disk" — two views of one instant — never
---      "what the model happens to hold now" vs "what disk held a moment ago".
---   2. Everything on the BufWritePost path is synchronous: `read_file_bytes`
---      uses blocking `vim.uv` calls and `on_bytes` is a synchronous callback,
---      so no buffer change can interleave between the anchor and the compare.
---
--- NO BEHAVIOUR CHANGE accompanies this file. It is here so that a future
--- refactor toward async I/O — or one that drops/reorders `reconcile_save` —
--- cannot silently reintroduce the defect. Note that none of these tests call
--- `vim.wait`: the assertions hold the instant `:write` returns, which is
--- itself the synchrony pin.
---
--- Mirrors doc_wiring_external_change_spec.lua's scratch harness.
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local coordinator_mod = require("provenance.recorder.watch.external_change_coordinator")
local sha256 = require("provenance.core.sha256")

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

  function scratch.read_file(path)
    local uv = vim.uv or vim.loop
    local fd = assert(uv.fs_open(path, "r", 420))
    local stat = assert(uv.fs_fstat(fd))
    local raw = stat.size > 0 and uv.fs_read(fd, stat.size, 0) or ""
    uv.fs_close(fd)
    return raw
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

--- A delta appending `text` at the very end of `content`.
local function append_delta(content, text)
  local line = 0
  for _ in content:gmatch("\n") do
    line = line + 1
  end
  local last_line_len = #(content:match("[^\n]*$") or "")
  local pos = { line = line, character = last_line_len }
  return { range = { start = pos, ["end"] = pos }, text = text }
end

describe("doc_wiring save-time race (D1) regression pins", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
    vim.o.autoread = false
  end)

  --- T1 — the regression pin.
  ---
  --- Put the expected-content model AHEAD of the buffer before the save: this
  --- is exactly the state a keystroke landing inside an async read window
  --- leaves behind in the other two recorders. Because `reconcile_save`
  --- re-anchors the model to the written bytes before anything is compared,
  --- the divergence cannot produce an event, and the model is left agreeing
  --- with disk rather than rolled backwards onto a stale snapshot.
  it("T1: a model that has moved past the buffer produces NO fs.external_change on save", function()
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

    -- The race: the model advances past what is about to be written.
    local ec = scratch.coordinator.registry.get("foo.txt")
    assert.is_not_nil(ec)
    scratch.coordinator.apply_change("foo.txt", { append_delta(ec.get_content(), "x") })
    assert.equals("changed\nline2\nx", ec.get_content())

    vim.cmd("write")

    assert.is_not_nil(find(events, "doc.save"))
    assert.equals(
      0,
      count(events, "fs.external_change"),
      "the editor's own save must never be reported as an external change"
    )
    -- Anchored to the written bytes, not rolled backwards to a stale snapshot.
    local on_disk = scratch.read_file(path)
    assert.equals(on_disk, scratch.coordinator.registry.get("foo.txt").get_content())
  end)

  --- T2 — the anti-regression.
  ---
  --- Same save path, but something genuinely else writes the file after Neovim
  --- flushes and before the check reads it. That content was never a buffer
  --- state, so it must still be reported — exactly once, with the correct
  --- direction — and the model must be reseeded to disk reality. A recorder
  --- that bought quiet by going blind here would be worse than the bug.
  it("T2: a genuine external write between the flush and the check is still reported exactly once", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")
    local clobber = "import os\nos.system('rm -rf /')\n"

    local events, emit = new_emit()
    scratch.coordinator = coordinator_mod.start({
      workspace = workspace,
      files_under_review = { "foo.txt" },
      emit = emit,
    })

    -- Delegate to the real coordinator, but clobber the file on disk at the
    -- one instant between the anchor (reconcile_save) and the compare
    -- (check_after_save).
    local written_at_save
    local ec_deps = {
      seed_open = scratch.coordinator.seed_open,
      apply_change = scratch.coordinator.apply_change,
      reconcile_save = function(rel, written)
        written_at_save = written
        scratch.coordinator.reconcile_save(rel, written)
      end,
      note_save = function(rel)
        scratch.coordinator.note_save(rel)
        scratch.write_file(path, clobber)
      end,
      check_after_save = scratch.coordinator.check_after_save,
    }

    scratch.handle = doc_wiring.attach({
      workspace = workspace,
      emit = emit,
      external_change = ec_deps,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "changed" })
    vim.cmd("write")

    assert.equals(1, count(events, "fs.external_change"), "a real external write must still be reported")
    local ev = find(events, "fs.external_change")
    assert.equals("foo.txt", ev.data.path)
    assert.equals("modify", ev.data.operation)
    -- Direction: old = what the editor wrote, new = the clobbered on-disk bytes.
    assert.equals(sha256.hex(written_at_save), ev.data.old_hash)
    assert.equals(sha256.hex(clobber), ev.data.new_hash)
    -- Reseeded to disk reality so subsequent edits chain from the truth.
    assert.equals(clobber, scratch.coordinator.registry.get("foo.txt").get_content())
  end)

  --- T3 — no self-perpetuation.
  ---
  --- The backwards reset is what turned one mistimed keystroke into a mirrored
  --- PAIR of events elsewhere: the model was left behind the buffer, so the
  --- next save mismatched too. Run T1, then save again with nothing interleaved.
  it("T3: after the T1 scenario, the next clean save is also silent", function()
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
    local ec = scratch.coordinator.registry.get("foo.txt")
    scratch.coordinator.apply_change("foo.txt", { append_delta(ec.get_content(), "x") })
    vim.cmd("write")
    assert.equals(0, count(events, "fs.external_change"))

    -- A second, entirely clean save: no interleaved edit, nothing external.
    vim.api.nvim_buf_set_lines(buf, 1, 2, false, { "second" })
    vim.cmd("write")

    assert.equals(2, count(events, "doc.save"))
    assert.equals(
      0,
      count(events, "fs.external_change"),
      "the mirrored second event of the pair must not appear either"
    )
    assert.equals(scratch.read_file(path), scratch.coordinator.registry.get("foo.txt").get_content())
  end)
end)
