--- Tests for reload_checker (Plan 5, Task 7 — Path 3: reload-from-disk,
--- `FileChangedShellPost`). Headless, real buffers + real `vim.uv` file I/O
--- against a temp workspace dir; a real ExpectedContentRegistry/
--- ExpectedContent; a fake `emit` capturing {kind, data}; a controllable-clock
--- ExplanationTagger.
local checker_mod = require("provenance.recorder.watch.reload_checker")
local registry_mod = require("provenance.recorder.state.expected_content_registry")
local tagger_mod = require("provenance.recorder.events.explanation_tags")
local sha256 = require("provenance.core.sha256")

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

--- Track everything created by a test so it can be torn down afterward:
--- buffers wiped, temp dirs deleted. Mirrors doc_wiring_spec.lua's
--- new_scratch.
local function new_scratch()
  local scratch = { bufs = {}, dirs = {} }

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

  function scratch.teardown()
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

describe("reload_checker", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
    -- Integration test flips these; restore defaults for later specs.
    vim.o.autoread = false
  end)

  it("external change: emits ONE fs.external_change with correct direction and resets the model", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/a.py"
    local expected_content = "print('hello')\n"
    scratch.write_file(path, expected_content)

    local buf = scratch.edit(path)

    local reg = registry_mod.new({ "a.py" })
    local ec = reg.get_or_create("a.py", expected_content)

    -- Simulate an external write that Neovim then reloaded: buffer content
    -- now equals `disk_content`, but the ExpectedContent model still holds
    -- `expected_content` (the reload handler reads disk directly, so we
    -- don't even need the buffer's own lines to match).
    local disk_content = "print('overwritten externally')\n"
    scratch.write_file(path, disk_content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    checker.on_file_changed_shell(buf)

    assert.equals(1, #events)
    local ev = events[1]
    assert.equals("fs.external_change", ev.kind)
    assert.equals("a.py", ev.data.path)
    assert.equals(sha256.hex(expected_content), ev.data.old_hash) -- EXPECTED (editor believed)
    assert.equals(sha256.hex(disk_content), ev.data.new_hash) -- ACTUAL (on disk)
    assert.equals("modify", ev.data.operation)
    assert.is_number(ev.data.new_content_size)
    assert.equals(#disk_content, ev.data.new_content_size)
    assert.equals(disk_content, ev.data.new_content) -- <= 4096 bytes: inlined
    assert.is_nil(ev.data.explanation) -- no tagger mark

    -- The ExpectedContent model must be reset to disk reality AFTER emitting.
    assert.equals(disk_content, ec.get_content())
    assert.equals(sha256.hex(disk_content), ec.hash())
  end)

  it("no-op reload: on-disk content matches expected -> no emit", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/a.py"
    local content = "unchanged\n"
    scratch.write_file(path, content)

    local buf = scratch.edit(path)

    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    checker.on_file_changed_shell(buf)

    assert.equals(0, #events)
  end)

  it("untracked file: no registry entry -> no-op (no emit, no error)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/never.py"
    scratch.write_file(path, "some content\n")

    local buf = scratch.edit(path)

    local reg = registry_mod.new({}) -- "never.py" not in files_under_review

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    assert.has_no.errors(function()
      checker.on_file_changed_shell(buf)
    end)

    assert.equals(0, #events)
  end)

  it("buffer outside workspace: no-op (no emit, no error)", function()
    local workspace = scratch.workspace()
    local outside_dir = scratch.workspace() -- a second, sibling temp dir
    local path = outside_dir .. "/a.py"
    scratch.write_file(path, "content\n")

    local buf = scratch.edit(path)

    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", "different content\n")

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    assert.has_no.errors(function()
      checker.on_file_changed_shell(buf)
    end)

    assert.equals(0, #events)
  end)

  it("empty buffer name: no-op (no emit, no error)", function()
    local workspace = scratch.workspace()

    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", "content\n")

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    -- An unnamed scratch buffer: nvim_buf_get_name returns "".
    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)

    assert.has_no.errors(function()
      checker.on_file_changed_shell(buf)
    end)

    assert.equals(0, #events)
  end)

  it("explanation: a fresh formatter mark on the tagger surfaces as data.explanation", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/a.py"
    scratch.write_file(path, "old content\n")

    local buf = scratch.edit(path)

    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", "old content\n")

    local disk_content = "new content from formatter\n"
    scratch.write_file(path, disk_content)

    local events, emit = new_emit()
    local now = 0
    local tagger = tagger_mod.new({ get_now = function() return now end })
    tagger.mark_formatter()
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    checker.on_file_changed_shell(buf)

    assert.equals(1, #events)
    assert.equals("formatter", events[1].data.explanation)
  end)

  it("no explanation: without a fresh tagger mark, data.explanation is absent (nil)", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/a.py"
    scratch.write_file(path, "old content\n")

    local buf = scratch.edit(path)

    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", "old content\n")

    local disk_content = "new content, no tool ran\n"
    scratch.write_file(path, disk_content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    checker.on_file_changed_shell(buf)

    assert.equals(1, #events)
    assert.is_nil(events[1].data.explanation)
  end)

  it("large content (> 4096 bytes): new_content_head/new_content_tail set instead of new_content", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/big.py"
    scratch.write_file(path, "small\n")

    local buf = scratch.edit(path)

    local reg = registry_mod.new({ "big.py" })
    reg.get_or_create("big.py", "small\n")

    local disk_content = string.rep("x", 5000)
    scratch.write_file(path, disk_content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    checker.on_file_changed_shell(buf)

    assert.equals(1, #events)
    local data = events[1].data
    assert.equals(5000, data.new_content_size)
    assert.is_nil(data.new_content)
    assert.is_string(data.new_content_head)
    assert.is_string(data.new_content_tail)
  end)

  it("INTEGRATION: autoread + :checktime drives a real FileChangedShellPost reload", function()
    local workspace = scratch.workspace()
    local path = workspace .. "/a.py"
    local expected_content = "print('hello')\n"
    scratch.write_file(path, expected_content)

    local buf = scratch.edit(path)

    local reg = registry_mod.new({ "a.py" })
    local ec = reg.get_or_create("a.py", expected_content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, workspace = workspace, emit = emit, tagger = tagger })

    local augroup = vim.api.nvim_create_augroup("ReloadCheckerSpecIntegration", { clear = true })
    vim.api.nvim_create_autocmd("FileChangedShellPost", {
      group = augroup,
      callback = function(args)
        checker.on_file_changed_shell(args.buf)
      end,
    })

    -- Write DIFFERENT content to disk externally, outside the editor, via
    -- vim.uv directly (not :write) — Neovim has no idea this happened yet.
    local disk_content = "print('changed on disk externally')\n"
    scratch.write_file(path, disk_content)

    vim.bo[buf].autoread = true
    vim.o.autoread = true
    vim.cmd("checktime")

    pcall(vim.api.nvim_del_augroup_by_name, "ReloadCheckerSpecIntegration")

    assert.equals(1, #events)
    local ev = events[1]
    assert.equals("fs.external_change", ev.kind)
    assert.equals("a.py", ev.data.path)
    assert.equals(sha256.hex(expected_content), ev.data.old_hash)
    assert.equals(sha256.hex(disk_content), ev.data.new_hash)
    assert.equals("modify", ev.data.operation)

    assert.equals(disk_content, ec.get_content())
  end)
end)
