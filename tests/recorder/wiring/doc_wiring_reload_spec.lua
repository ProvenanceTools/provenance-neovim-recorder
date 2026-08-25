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
--- Neovim implementation detail this port depends on. doc_wiring DOES now
--- supply `on_reload` (see below), so if that callback ever grows an emit,
--- or if a future Neovim starts reporting reloads as ordinary `on_bytes`
--- splices, `provjet`'s fabricated paste appears here too. These tests fail
--- loudly if either happens.
---
--- THE SECOND HALF OF THE CONTRACT (the `describe` block's back half): a
--- reload must not be silently UNDER-reported either. Neovim drops any
--- buffer listener that supplies no `on_reload`, and it delivers that
--- `on_detach` AFTER doc_wiring's own BufReadPost handler has already run
--- and early-returned on its still-true `attached_bufs[buf]` — so nothing
--- re-attaches, and every keystroke after a `git pull` used to vanish from
--- the record. doc_wiring now supplies `on_reload`, which keeps the buffer
--- attached and re-seeds `buf_shadow` from the reloaded content without
--- emitting anything. Both halves are pinned here because they pull in
--- opposite directions: the cheap way to satisfy either one alone is to
--- break the other.
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

  -----------------------------------------------------------------------
  -- Surviving the reload (the OTHER half of the reload contract).
  --
  -- The tests above pin that a reload is never OVER-reported (as a paste).
  -- These pin that it is never silently UNDER-reported either: Neovim
  -- unloads buffer listeners across a reload, so a listener that supplies
  -- no `on_reload` is handed `on_detach` and dropped. Verified against
  -- Neovim 0.12.1:
  --
  --   with on_reload:    BufReadPre -> BufReadPost -> on_reload  -> FileChangedShellPost   (stays attached)
  --   without on_reload: BufReadPre -> BufReadPost -> on_detach  -> FileChangedShellPost   (dropped)
  --
  -- Note where `on_detach` lands: AFTER doc_wiring's own BufReadPost
  -- handler has already run and early-returned on its still-true
  -- `attached_bufs[buf]` bookkeeping. So BufReadPost cannot re-attach — it
  -- ran too early — and nothing else ever will. That is what made every
  -- post-`git pull` keystroke vanish from the record.
  -----------------------------------------------------------------------

  it("keystrokes AFTER a reload are still recorded — the buffer survives the reload attached", function()
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
    assert.equals("ArrayDeque.java", scratch.doc_handle.recordable_rel(buf))

    scratch.write_file(path, PULLED_BLOCK)
    vim.bo[buf].autoread = true
    vim.o.autoread = true
    vim.cmd("checktime")

    -- The buffer is still a tracked, recordable buffer after the reload.
    assert.equals("ArrayDeque.java", scratch.doc_handle.recordable_rel(buf))

    -- Now the student types. This MUST be recorded — it is their own work,
    -- and it is the work that follows every `git pull` in a real session.
    local before = count(events, "doc.change")
    vim.api.nvim_buf_set_text(buf, 1, 2, 1, 2, { "x" })
    assert.equals(before + 1, count(events, "doc.change"))
  end)

  it("the post-reload delta is computed against the RELOADED content, not a stale pre-reload shadow", function()
    -- Re-attaching without re-seeding `buf_shadow` would be worse than the
    -- gap it fixes: precise_delta resolves UTF-16 columns against the
    -- shadow, and utf16_col CLAMPS to the line's length, so a shadow still
    -- holding the short pre-reload line silently collapses a real range
    -- onto that line's end instead of erroring. The recorded delta would be
    -- quietly wrong rather than absent, and replay would diverge.
    local workspace = scratch.workspace()
    local path = workspace .. "/ArrayDeque.java"
    -- Line 0 is ONE character before the reload...
    scratch.write_file(path, "x\nkeep\n")

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

    -- ...and SIXTEEN characters after it.
    scratch.write_file(path, "abcdefghijklmnop\nkeep\n")
    vim.bo[buf].autoread = true
    vim.o.autoread = true
    vim.cmd("checktime")
    assert.same({ "abcdefghijklmnop", "keep" }, vim.api.nvim_buf_get_lines(buf, 0, -1, false))

    -- Replace characters [4, 9) of the reloaded line 0 — a range that does
    -- not even EXIST in the pre-reload line "x".
    vim.api.nvim_buf_set_text(buf, 0, 4, 0, 9, { "ZZ" })

    local ev = find(events, "doc.change")
    assert.is_not_nil(ev)
    local delta = ev.data.deltas[1]
    assert.equals("ZZ", delta.text)
    -- A stale shadow would clamp BOTH of these to character 1 (the length
    -- of the pre-reload "x").
    assert.same({ line = 0, character = 4 }, delta.range.start)
    assert.same({ line = 0, character = 9 }, delta.range["end"])
  end)

  it("surviving the reload does not re-report it: still exactly one doc.open and one fs.external_change", function()
    -- Re-attachment must not fabricate a second doc.open baseline. The
    -- expected-content model is already reset to disk reality by
    -- reload_checker (`ec.reset(on_disk_content)` after it emits), so a
    -- fresh doc.open would be redundant at best; at worst the analyzer
    -- would replay a full-content doc.open ON TOP of the
    -- fs.external_change content for the same bytes.
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
    scratch.write_file(path, PULLED_BLOCK)
    vim.bo[buf].autoread = true
    vim.o.autoread = true
    vim.cmd("checktime")

    assert.equals(1, count(events, "doc.open"))
    assert.equals(1, count(events, "fs.external_change"))
    assert.equals(0, count(events, "paste"))
    assert.equals(0, count(events, "doc.change"))

    -- The coordinator's model is disk reality, set by reload_checker — not
    -- by anything doc_wiring did on re-attach.
    assert.equals(PULLED_BLOCK, scratch.coordinator.registry.get("ArrayDeque.java").get_content())
  end)
end)
