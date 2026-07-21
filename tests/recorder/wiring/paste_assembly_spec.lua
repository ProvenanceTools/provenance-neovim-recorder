--- paste_assembly: the Plan 6 assembly wiring the three paste-detection
--- signals into doc_wiring's on_lines path. Headless, REAL buffers, REAL
--- `vim.paste`, REAL doc_wiring — no editor-API mocking, matching this
--- repo's convention for wiring-layer specs (see doc_wiring_spec.lua,
--- paste_intercept_spec.lua).
---
--- PORT NOTE: doc_wiring drives paste detection off `on_bytes` (precise,
--- byte-granular edits), not `on_lines`. A single-shot `vim.paste()` produces
--- exactly one on_bytes edit, so the correlator still sees exactly one delta —
--- but that delta now carries the PRECISE character range and EXACTLY the
--- pasted text (no synthetic trailing EOL), the same shape VS Code emits. The
--- "real paste" test below drives the paste through the genuine path: a real
--- global `vim.paste` (wrapped by the real paste_intercept, feeding signals
--- 2/3) applied directly to the RECORDABLE buffer (a real on_bytes callback,
--- through the real doc_wiring attach + real router + real correlator) — no
--- decoy buffer or manual buffer-mutation workaround needed.
---
--- paste_correlator.is_paste_shaped requires a SINGLE delta (never an empty
--- range specifically), which a real single-shot `vim.paste()` always
--- produces.
local doc_wiring = require("provenance.recorder.wiring.doc_wiring")
local paste_assembly = require("provenance.recorder.wiring.paste_assembly")
local sha256 = require("provenance.core.sha256")

--- Plenary's directory test runner spawns one REAL `nvim --headless`
--- SUBPROCESS per spec file, run concurrently (plenary/test_harness.lua:
--- Job:start() per file, not sequential by default). On macOS (and anywhere
--- else with a real `pbcopy`/`pbpaste`-style clipboard tool on PATH), the
--- `"+`/`"*` registers are backed by the ACTUAL OS pasteboard — a resource
--- shared across ALL those concurrent processes, not per-process. Any spec
--- file that both writes and reads `"+`/`"*` therefore races every other
--- concurrently-running spec file doing the same (this repo's pre-existing
--- paste_intercept_spec.lua already does), which is exactly what caused an
--- observed cross-file flake against this content: `make test` intermittently
--- had paste_intercept_spec.lua's "empty registers" test read back a
--- 32-char "p" string this file had just written to `"+`.
---
--- Fix (test-file-local, no production code touched): install a `g:clipboard`
--- provider backed by a private in-process Lua table instead of the real
--- pasteboard. `vim.fn.setreg("+"/"*", ...)` and `vim.fn.getreg(...)` still
--- run for real (paste_intercept.lua's capture_text still calls the real
--- Neovim register API) — only the STORAGE backing "+`/`"*` is redirected
--- off the shared OS resource, onto memory scoped to this process.
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
    -- Belt-and-braces: a leaked global vim.paste override would corrupt
    -- every subsequent paste-related spec in this headless process.
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

describe("paste_assembly.attach", function()
  local scratch

  before_each(function()
    install_local_clipboard()
    scratch = new_scratch()
    -- Clear clipboard registers so no stale content from a prior test
    -- accidentally content-matches a later test's typed text.
    vim.fn.setreg("+", "")
    vim.fn.setreg("*", "")
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("real paste (>=30 chars, via real vim.paste applied directly to the recordable buffer) -> exactly one `paste` event with content/length/sha256/range", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
    })

    local buf = scratch.edit(path)

    local clip = string.rep("p", 32) -- >=30 chars, no newline
    assert.is_true(#clip >= 30)

    -- Real vim.paste, applied directly to the RECORDABLE buffer's single
    -- (initially empty) line. This drives BOTH the real paste_intercept
    -- wrapping (signals 2/3, since vim.paste is a single global seam, not
    -- per-buffer) AND a real on_lines callback through doc_wiring's actual
    -- buffer attach (signal 1 + the router) -- no decoy buffer needed.
    vim.fn.setreg("+", clip)
    vim.paste({ clip }, -1)

    assert.equals(1, count(events, "paste"))
    local ev = find(events, "paste")
    assert.equals("foo.txt", ev.data.path)

    -- Precise on_bytes deltas carry EXACTLY the pasted text (no synthetic
    -- trailing EOL), matching VS Code's paste content shape.
    assert.equals(clip, ev.data.content)
    assert.equals(#clip, ev.data.length)
    assert.equals(sha256.hex(clip), ev.data.sha256)
    assert.is_nil(ev.data.content_head)
    assert.is_nil(ev.data.content_tail)

    -- A pure insertion into the empty line: a precise empty range at the
    -- insertion point (start == end), UTF-16 character columns. This is the
    -- same shape VS Code emits for a paste.
    assert.is_not_nil(ev.data.range)
    assert.same({ line = 0, character = 0 }, ev.data.range.start)
    assert.same({ line = 0, character = 0 }, ev.data.range["end"])

    -- No doc.change fired for this same edit (routed to `paste` instead).
    assert.equals(0, count(events, "doc.change"))
  end)

  it("typing (<30 chars, no newline) -> doc.change source=typed (router preserves typed for non-pastes)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
    })

    local buf = scratch.edit(path)
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, { "hi" })

    assert.equals(1, count(events, "doc.change"))
    local ev = find(events, "doc.change")
    assert.equals("foo.txt", ev.data.path)
    assert.equals("typed", ev.data.source)
    assert.equals(0, count(events, "paste"))
  end)

  it("bulk multi-line insert (>=30 chars, newline, non-empty range, no intercept) -> paste (single delta is shape-fit regardless of range)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
    })

    local buf = scratch.edit(path)
    -- Replace existing line 0 (non-empty range: first=0, last=1) with
    -- several lines totalling >=30 chars -- a single delta whose text
    -- contains embedded newlines, classified paste_likely by rule 1 (single
    -- delta >= 30 chars) regardless of the embedded newline. doc_wiring's
    -- on_lines always produces exactly ONE delta per callback, so this is
    -- still shape-fit (is_paste_shaped only checks #deltas == 1, not range
    -- emptiness -- see paste_correlator.lua) and routes to `paste`, not
    -- `doc.change source=paste_likely` -- that source is only reachable via
    -- a genuine multi-delta input, which doc_wiring never produces (see
    -- paste_conformance_spec.lua's DocChangePayload test for how that shape
    -- is still proven).
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, {
      string.rep("a", 15),
      string.rep("b", 15),
      string.rep("c", 15),
    })

    assert.equals(1, count(events, "paste"))
    local ev = find(events, "paste")
    assert.equals("foo.txt", ev.data.path)
    assert.equals(0, count(events, "doc.change"))
  end)

  it("diverging intercept/large-insert counts -> paste.anomaly with per-interval deltas", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    -- Short real interval + tolerance=0 so a single-unit divergence (one
    -- large_insert, zero intercepts) trips the anomaly on the next real
    -- timer tick, without needing to reach into assembly internals.
    scratch.assembly_handle = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
      interval_ms = 20,
      tolerance = 0,
    })

    local buf = scratch.edit(path)
    -- A bulk paste_likely edit with NO intercept: large_insert_count
    -- increments, intercepted_count does not -> divergence.
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
    assert.equals(0, ev.data.intercepted_count)
    assert.equals(1, ev.data.large_insert_count)
  end)

  it("dispose() unhooks the router (edit reverts to source=typed default), restores vim.paste, and stops the reconciler timer", function()
    local orig_paste = vim.paste

    local workspace = scratch.workspace()
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line1\nline2\n")

    local events, emit = new_emit()
    scratch.doc_handle = doc_wiring.attach({ workspace = workspace, emit = emit })
    local assembly = paste_assembly.attach({
      emit = emit,
      doc_wiring_handle = scratch.doc_handle,
      interval_ms = 20,
      tolerance = 0,
    })
    scratch.assembly_handle = nil -- disposed manually below; don't double-dispose in teardown

    assert.is_not.equals(orig_paste, vim.paste)

    local buf = scratch.edit(path)
    -- A bulk edit BEFORE dispose, to prove the assembly is live. Single
    -- delta, paste_likely-classified, no intercept -> routes to a `paste`
    -- event (is_paste_shaped only requires a single delta now, not an empty
    -- range -- see paste_correlator.lua and the "bulk multi-line insert"
    -- test above).
    vim.api.nvim_buf_set_lines(buf, 0, 1, false, {
      string.rep("a", 15),
      string.rep("b", 15),
      string.rep("c", 15),
    })
    assert.equals(1, count(events, "paste"))
    assert.equals(0, count(events, "doc.change"))

    assembly.dispose()

    assert.equals(orig_paste, vim.paste)

    local before = #events
    -- Post-dispose edit: default doc_wiring routing (source=typed), even
    -- though this edit would otherwise classify paste_likely.
    vim.api.nvim_buf_set_lines(buf, 1, 2, false, {
      string.rep("z", 40),
    })
    local ev = find(events, "doc.change")
    -- Most recent doc.change (index-based: last one appended).
    local last_change
    for _, e in ipairs(events) do
      if e.kind == "doc.change" then
        last_change = e
      end
    end
    assert.equals("typed", last_change.data.source)
    assert.is_true(#events > before)

    -- Reconciler timer stopped: no further paste.anomaly even after
    -- waiting past several would-be intervals.
    local anomaly_count_before = count(events, "paste.anomaly")
    vim.wait(100, function()
      return false
    end, 10)
    assert.equals(anomaly_count_before, count(events, "paste.anomaly"))

    -- Idempotent.
    assert.has_no.errors(function()
      assembly.dispose()
    end)
  end)

  it("CONCURRENCY: a paste in session B's buffer is never seen by session A's correlator", function()
    local workspace_a = scratch.workspace()
    local workspace_b = scratch.workspace()
    local path_a = workspace_a .. "/a.txt"
    local path_b = workspace_b .. "/b.txt"
    scratch.write_file(path_a, "aaa\n")
    scratch.write_file(path_b, "bbb\n")

    local events_a, emit_a = new_emit()
    local events_b, emit_b = new_emit()

    local doc_a = doc_wiring.attach({ workspace = workspace_a, emit = emit_a })
    local doc_b = doc_wiring.attach({ workspace = workspace_b, emit = emit_b })
    local assembly_a = paste_assembly.attach({ emit = emit_a, doc_wiring_handle = doc_a })
    local assembly_b = paste_assembly.attach({ emit = emit_b, doc_wiring_handle = doc_b })

    local buf_b = scratch.edit(path_b)
    -- `marker` is embedded inside `clip` as an exact substring. `clip` is
    -- >=30 chars (so B's OWN session correctly classifies its own paste as
    -- paste_likely by shape, matching realistic behavior); `marker` alone
    -- is well under 30 chars and single-line, so paste_classifier.
    -- classify_change on `marker` ALONE (see paste_classifier.lua rule 1/2)
    -- returns "typed" -- shape can never explain a `paste` verdict for A's
    -- edit below. The ONLY way A's short edit could resolve to `paste`
    -- is CONTENT-matching (paste_correlator.matches: equality-or-
    -- substring, see paste_correlator.lua) a polluted `pending` that
    -- session B's intercept has no business setting on session A's
    -- correlator. That is exactly the bug the ownership gate in
    -- paste_assembly.lua's on_intercept closure fixes: without it, EVERY
    -- session's correlator receives EVERY intercepted paste (paste_
    -- intercept.lua's `broadcast` fans out to all listeners), so B's
    -- paste would set A's `pending = { text = clip, at = ... }` too.
    local marker = "SESSION_B_MARKER"
    assert.is_true(#marker < 30)
    local clip = string.rep("Q", 10) .. marker .. string.rep("Q", 10)
    assert.is_true(#clip >= 30)
    assert.is_not_nil(clip:find(marker, 1, true))

    vim.fn.setreg("+", clip)
    vim.paste({ clip }, -1)

    -- Session B (the owning session) sees the paste.
    local paste_ev_b = find(events_b, "paste")
    assert.is_not_nil(paste_ev_b)

    -- Session A never sees a paste event from B's intercept.
    assert.is_nil(find(events_a, "paste"))

    -- Session A's own next edit: a SHORT (well under 30 chars), single-
    -- line, single-delta INSERTION (via nvim_buf_set_text, not
    -- nvim_buf_set_lines -- replacing the buffer's only line with
    -- nvim_buf_set_lines hits doc_wiring's whole-line-op branch, which
    -- appends the buffer's trailing EOL onto the reported inserted text;
    -- that extra "\n" would make `marker` fail its substring match against
    -- `clip` regardless of the gate, silently un-discriminating the test
    -- again) whose text is an exact substring of B's clip. Shape alone
    -- (paste_classifier) calls this "typed" -- it is neither long enough
    -- (rule 1) nor multi-delta-with-newline (rule 2). If the ownership
    -- gate is missing, B's clip is still sitting in A's correlator's
    -- `pending` and this substring-matching insert wrongly CONFIRMS as a
    -- `paste` event (paste_correlator.on_doc_change's `confirmed` branch).
    -- With the gate present, A's `pending` was never polluted, so this
    -- resolves correctly to `doc.change`/`source = "typed"`.
    local buf_a = scratch.edit(path_a)
    vim.api.nvim_buf_set_text(buf_a, 0, 0, 0, 0, { marker })

    assert.is_nil(find(events_a, "paste"))
    local change_ev_a = find(events_a, "doc.change")
    assert.is_not_nil(change_ev_a)
    assert.equals("typed", change_ev_a.data.source)

    assembly_a.dispose()
    assembly_b.dispose()
    doc_a.dispose()
    doc_b.dispose()
  end)
end)
