--- Tests for save_time_checker (Plan 5, Task 5 — Path 1: save-time hash
--- check). Headless, real vim.uv file I/O against a temp workspace dir; a
--- real ExpectedContentRegistry/ExpectedContent; a fake `emit` capturing
--- {kind, data}; a controllable-clock ExplanationTagger.
local checker_mod = require("provenance.recorder.watch.save_time_checker")
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

local function write_file(path, content)
  local uv = vim.uv or vim.loop
  local fd = assert(uv.fs_open(path, "w", 420))
  if #content > 0 then
    assert(uv.fs_write(fd, content))
  end
  assert(uv.fs_close(fd))
end

describe("save_time_checker", function()
  local dir

  before_each(function()
    dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
  end)

  after_each(function()
    pcall(vim.fn.delete, dir, "rf")
  end)

  it("typed-then-clean-save: on-disk content matches expected -> no emit", function()
    local reg = registry_mod.new({ "a.py" })
    local content = "print('hello')\n"
    reg.get_or_create("a.py", content)

    local abs_path = dir .. "/a.py"
    write_file(abs_path, content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, emit = emit, tagger = tagger })

    checker.check_after_save("a.py", abs_path)

    assert.equals(0, #events)
  end)

  it("external change: emits ONE fs.external_change with correct direction and resets the model", function()
    local reg = registry_mod.new({ "a.py" })
    local expected_content = "print('hello')\n"
    local ec = reg.get_or_create("a.py", expected_content)

    local disk_content = "print('overwritten by formatter')\n"
    local abs_path = dir .. "/a.py"
    write_file(abs_path, disk_content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, emit = emit, tagger = tagger })

    checker.check_after_save("a.py", abs_path)

    assert.equals(1, #events)
    local ev = events[1]
    assert.equals("fs.external_change", ev.kind)
    assert.equals("a.py", ev.data.path)
    assert.equals(sha256.hex(expected_content), ev.data.old_hash) -- EXPECTED (editor believed)
    assert.equals(sha256.hex(disk_content), ev.data.new_hash) -- ACTUAL (on disk)
    assert.equals("modify", ev.data.operation)
    assert.is_number(ev.data.new_content_size)
    assert.equals(#disk_content, ev.data.new_content_size)
    assert.equals(disk_content, ev.data.new_content) -- <= 64 KB: inlined
    assert.is_nil(ev.data.explanation) -- no tagger mark

    -- The ExpectedContent model must be reset to disk reality AFTER emitting.
    assert.equals(disk_content, ec.get_content())
    assert.equals(sha256.hex(disk_content), ec.hash())
  end)

  it("explanation: a fresh formatter mark on the tagger surfaces as data.explanation", function()
    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", "old content\n")

    local disk_content = "new content from formatter\n"
    local abs_path = dir .. "/a.py"
    write_file(abs_path, disk_content)

    local events, emit = new_emit()
    local now = 0
    local tagger = tagger_mod.new({ get_now = function() return now end })
    tagger.mark_formatter()
    local checker = checker_mod.new({ registry = reg, emit = emit, tagger = tagger })

    checker.check_after_save("a.py", abs_path)

    assert.equals(1, #events)
    assert.equals("formatter", events[1].data.explanation)
  end)

  it("no explanation: without a fresh tagger mark, data.explanation is absent (nil)", function()
    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", "old content\n")

    local disk_content = "new content, no tool ran\n"
    local abs_path = dir .. "/a.py"
    write_file(abs_path, disk_content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, emit = emit, tagger = tagger })

    checker.check_after_save("a.py", abs_path)

    assert.equals(1, #events)
    assert.is_nil(events[1].data.explanation)
  end)

  it("never-opened file: registry has no entry -> no-op (no emit, no error)", function()
    local reg = registry_mod.new({})
    local abs_path = dir .. "/never.py"
    write_file(abs_path, "some content\n")

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, emit = emit, tagger = tagger })

    assert.has_no.errors(function()
      checker.check_after_save("never.py", abs_path)
    end)

    assert.equals(0, #events)
  end)

  it("read failure: on-disk path unreadable -> no-op (no emit, no throw)", function()
    local reg = registry_mod.new({ "a.py" })
    reg.get_or_create("a.py", "content\n")

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, emit = emit, tagger = tagger })

    assert.has_no.errors(function()
      checker.check_after_save("a.py", "/nonexistent/dir/x")
    end)

    assert.equals(0, #events)
  end)

  it("large content (> 64 KB): new_content_head/new_content_tail set instead of new_content", function()
    local reg = registry_mod.new({ "big.py" })
    reg.get_or_create("big.py", "small\n")

    local disk_content = string.rep("x", 70000)
    local abs_path = dir .. "/big.py"
    write_file(abs_path, disk_content)

    local events, emit = new_emit()
    local tagger = tagger_mod.new({ get_now = function() return 0 end })
    local checker = checker_mod.new({ registry = reg, emit = emit, tagger = tagger })

    checker.check_after_save("big.py", abs_path)

    assert.equals(1, #events)
    local data = events[1].data
    assert.equals(70000, data.new_content_size)
    assert.is_nil(data.new_content)
    assert.is_string(data.new_content_head)
    assert.is_string(data.new_content_tail)
  end)
end)
