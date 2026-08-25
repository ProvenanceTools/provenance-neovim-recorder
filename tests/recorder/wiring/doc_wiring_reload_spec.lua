--- Reload-from-disk must never be recorded as a paste (PRD §4.3 / §4.5).
---
--- WHY THIS SPEC EXISTS. The JetBrains recorder (`provjet`) shipped a
--- confirmed bug: when an external process rewrote a file the IDE had open
--- with a clean buffer (`git pull`, `git stash pop`), the IDE's reload
--- surfaced through the ORDINARY document-change path, arrived as one large
--- delta, was classified `PASTE_LIKELY`, and was emitted as a `paste` event
--- — recording a partner's pulled code as if the student had typed Cmd+V.
--- The same bytes were also (correctly) emitted as `fs.external_change`, so
--- the content was recorded twice: once truthfully, once as a fabrication.
--- The VS Code reference guards against this explicitly (doc-wiring.ts's
--- "Reload-from-disk detection" block: confirm the buffer converged to
--- on-disk bytes, emit `fs.external_change`, and `return` before the delta
--- reaches the paste classifier).
---
--- THIS PORT IS STRUCTURALLY IMMUNE, and that is what these tests pin.
--- Neovim does not replay a reload through `nvim_buf_attach`'s edit
--- callbacks at all. Verified against Neovim 0.12.1, an `autoread` +
--- `:checktime` reload delivers, in this exact order:
---
---     BufReadPre -> BufReadPost -> on_detach -> FileChangedShellPost
---
--- `on_bytes` never fires — Neovim unloads buffer listeners across a reload
--- (`on_reload` when the listener supplies one, else `on_detach`) rather
--- than synthesizing a splice. So there is no delta for the change-router /
--- paste_correlator to misclassify, and `paste` is unreachable from a
--- reload. Path 3 (`reload_checker`, via `FileChangedShellPost`) is the
--- ONLY thing that reports the reload, as `fs.external_change`.
---
--- THIS IS A LOAD-BEARING PIN, NOT A TAUTOLOGY. It is an assertion about a
--- Neovim implementation detail this port silently depends on. If a future
--- change gives doc_wiring's `nvim_buf_attach` an `on_reload` callback (a
--- plausible fix for the detach consequence noted below) and routes the
--- reloaded content through the change path, or if a future Neovim starts
--- reporting reloads as ordinary `on_bytes` splices, `provjet`'s fabricated
--- paste appears here too. These tests fail loudly if either happens.
---
--- NOTED, NOT FIXED (out of scope for this spec — see the task report): the
--- `on_detach` above is delivered AFTER doc_wiring's own BufReadPost handler
--- has already run and early-returned on its still-true `attached_bufs[buf]`
--- bookkeeping, so a reloaded buffer is left permanently detached and later
--- edits to it go unrecorded. That is an UNDER-recording bug, the opposite
--- failure from `provjet`'s, and it is deliberately not asserted here: these
--- tests must keep passing once it is fixed.
---
--- Headless, REAL buffers, REAL files on disk, REAL coordinator, REAL
--- `vim.paste` — matching this repo's convention for wiring-layer specs
--- (doc_wiring_spec.lua, paste_assembly_spec.lua).
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local paste_assembly = require("provenance.recorder.wiring.paste_assembly")
local coordinator_mod = require("provenance.recorder.watch.external_change_coordinator")

--- Redirect the `"+`/`"*` registers off the shared OS pasteboard onto an
--- in-process table. Verbatim in intent from paste_assembly_spec.lua — see
--- its docstring: plenary runs one real nvim subprocess PER SPEC FILE,
--- concurrently, and on macOS `"+` is backed by the actual system
--- pasteboard, so any two spec files that both touch it race each other.
local function install_local_clipboard()
  local store = { ["+"] = { {}, "v" }, ["*"] = { {}, "v" } }
  vim.g.clipboard = {
    name = "ProvenanceReloadSpecLocalClipboard",
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
  local scratch = { bufs = {}, dirs = {}, doc_handle = nil, assembly_handle = nil, coordinator = nil }

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

  function scratch.teardown()
    if scratch.assembly_handle then
      scratch.assembly_handle.dispose()
    end
    if scratch.doc_handle then
      scratch.doc_handle.dispose()
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

local function count(events, kind)
  local n = 0
  for _, ev in ipairs(events) do
    if ev.kind == kind then
      n = n + 1
    end
  end
  return n
end

--- A `git pull`-sized block: comfortably over paste_classifier's
--- PASTE_MIN_INSERT_CHARS (30) and multi-line, so it would satisfy BOTH
--- arms of the paste_likely rule if it ever reached the classifier. Sized
--- in the spirit of the real provjet bundle evidence (a 492-char reload
--- fabricated as `seq 301 paste`).
local PULLED_BLOCK = table.concat({
  "class ArrayDeque {",
  "  private int size;",
  "  // ---- pulled from a partner branch by `git pull`, not typed here ----",
  "  public void addFirst(int x) { /* partner's implementation */ }",
  "  public void addLast(int x) { /* partner's implementation */ }",
  "  public int removeFirst() { /* partner's implementation */ return 0; }",
  "}",
  "",
}, "\n")

describe("doc_wiring: reload-from-disk is never recorded as a paste", function()
  local scratch

  before_each(function()
    install_local_clipboard()
    scratch = new_scratch()
    -- No stale clipboard content that could content-match an edit below.
    vim.fn.setreg("+", "")
    vim.fn.setreg("*", "")
  end)

  after_each(function()
    scratch.teardown()
    vim.o.autoread = false
  end)

  it("a large external rewrite + autoread reload emits ONLY fs.external_change — no paste, no doc.change", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/ArrayDeque.java"
    local original = "class ArrayDeque {\n  private int size;\n}\n"
    scratch.write_file(path, original)

    local events, emit = new_emit()
    scratch.coordinator = coordinator_mod.start({
      workspace = workspace,
      scope = { track = { "ArrayDeque.java" }, ignore = {}, attachments = {} },
      emit = emit,
    })
    scratch.doc_handle = doc_wiring.attach({
      workspace = workspace,
      emit = emit,
      external_change = scratch.coordinator,
    })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
    })

    local buf = scratch.edit(path)
    assert.equals(1, count(events, "doc.open"))

    -- An external process (`git pull`) rewrites the file behind Neovim's
    -- back — via a plain file write, NOT `:write`, so Neovim has no idea.
    -- The buffer is clean, so `autoread` reloads it silently.
    scratch.write_file(path, PULLED_BLOCK)
    assert.is_true(#PULLED_BLOCK - #original >= 30)

    vim.bo[buf].autoread = true
    vim.o.autoread = true
    vim.cmd("checktime")

    -- The whole point: the pulled content is recorded ONCE, truthfully.
    assert.equals(1, count(events, "fs.external_change"))
    local ext = find(events, "fs.external_change")
    assert.equals("ArrayDeque.java", ext.data.path)
    assert.equals("modify", ext.data.operation)

    -- And NEVER as the student's own authorship.
    assert.equals(0, count(events, "paste"))
    assert.equals(0, count(events, "doc.change"))
  end)

  it("with NO external-change seam wired, a reload emits nothing at all — an unrecorded reload, never a fabricated paste", function()
    -- The accepted tradeoff (decided for provjet, mirrored here): where
    -- there is no ExpectedContent baseline there is no fs.external_change
    -- fallback, so the reload simply goes unrecorded. That is intended — an
    -- unrecorded reload beats a fabricated paste. What must NOT happen,
    -- under any wiring, is the reload surfacing as the student's own
    -- authorship. This drives the bare doc_wiring + paste_assembly pair
    -- (`external_change = nil`, the documented default) to prove the
    -- no-paste guarantee holds independently of the coordinator: nothing in
    -- it depends on Path 3 having "claimed" the change first.
    local workspace = scratch.workspace()
    local path = workspace .. "/ArrayDeque.java"
    scratch.write_file(path, "class ArrayDeque {\n  private int size;\n}\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
    })

    local buf = scratch.edit(path)
    assert.equals(1, count(events, "doc.open"))

    scratch.write_file(path, PULLED_BLOCK)

    vim.bo[buf].autoread = true
    vim.o.autoread = true
    vim.cmd("checktime")

    assert.equals(0, count(events, "paste"))
    assert.equals(0, count(events, "doc.change"))
    assert.equals(0, count(events, "fs.external_change"))
  end)

  it("a genuine paste of the SAME content still emits `paste` — the guard is about reloads, not about big inserts", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/ArrayDeque.java"
    scratch.write_file(path, "")

    local events, emit = new_emit()
    scratch.coordinator = coordinator_mod.start({
      workspace = workspace,
      scope = { track = { "ArrayDeque.java" }, ignore = {}, attachments = {} },
      emit = emit,
    })
    scratch.doc_handle = doc_wiring.attach({
      workspace = workspace,
      emit = emit,
      external_change = scratch.coordinator,
    })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
    })

    scratch.edit(path)

    -- Same bytes as the reload above, but arriving through the real
    -- `vim.paste` seam: the student really did paste this.
    local clip = "public void addFirst(int x) { /* pasted by the student */ }"
    assert.is_true(#clip >= 30)
    vim.fn.setreg("+", clip)
    vim.paste({ clip }, -1)

    assert.equals(1, count(events, "paste"))
    local ev = find(events, "paste")
    assert.equals("ArrayDeque.java", ev.data.path)
    assert.equals(clip, ev.data.content)
    assert.equals(#clip, ev.data.length)
    assert.equals(0, count(events, "doc.change"))
  end)

  it("an ordinary typed edit still emits doc.change source=typed", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/ArrayDeque.java"
    scratch.write_file(path, "class ArrayDeque {\n  private int size;\n}\n")

    local events, emit = new_emit()
    scratch.coordinator = coordinator_mod.start({
      workspace = workspace,
      scope = { track = { "ArrayDeque.java" }, ignore = {}, attachments = {} },
      emit = emit,
    })
    scratch.doc_handle = doc_wiring.attach({
      workspace = workspace,
      emit = emit,
      external_change = scratch.coordinator,
    })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_text(buf, 1, 2, 1, 2, { "x" })

    assert.equals(1, count(events, "doc.change"))
    local ev = find(events, "doc.change")
    assert.equals("ArrayDeque.java", ev.data.path)
    assert.equals("typed", ev.data.source)
    assert.equals(0, count(events, "paste"))
    assert.equals(0, count(events, "fs.external_change"))
  end)
end)
