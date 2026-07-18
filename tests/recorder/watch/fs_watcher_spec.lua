--- Tests for fs_watcher (Plan 5, Task 6 — Path 2: vim.uv external-change
--- watcher). Headless, real vim.uv file I/O against a temp workspace dir; a
--- real ExpectedContentRegistry/ExpectedContent; a fake `emit` capturing
--- {kind, data}; a controllable clock + recent_saves table.
---
--- Most cases drive handle.handle_path_event(rel, abs_path) directly — a
--- deterministic decision handler with no waiting involved. Exactly one
--- test ("integration") exercises the real vim.uv.new_fs_poll() seam via
--- vim.wait on a generous, latency-tolerant timeout.
local fs_watcher = require("provenance.recorder.watch.fs_watcher")
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

local function delete_file(path)
  local uv = vim.uv or vim.loop
  uv.fs_unlink(path)
end

describe("fs_watcher", function()
  local dir
  local handles

  before_each(function()
    dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    handles = {}
  end)

  after_each(function()
    for _, h in ipairs(handles) do
      pcall(h.dispose)
    end
    handles = {}
    pcall(vim.fn.delete, dir, "rf")
  end)

  local function track(h)
    table.insert(handles, h)
    return h
  end

  -------------------------------------------------------------------------
  -- (A) handle_path_event — direct, deterministic cases.
  -------------------------------------------------------------------------

  describe("handle_path_event — modify", function()
    it("external modify: emits ONE operation=modify with correct direction, content fields, and resets ec", function()
      local reg = registry_mod.new({ "a.py" })
      local original = "print('hello')\n"
      local ec = reg.get_or_create("a.py", original)

      local abs_path = dir .. "/a.py"
      local disk_content = "print('overwritten externally')\n"
      write_file(abs_path, disk_content)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        get_now = function() return 0 end,
      }))

      watch.handle_path_event("a.py", abs_path)

      assert.equals(1, #events)
      local ev = events[1]
      assert.equals("fs.external_change", ev.kind)
      assert.equals("a.py", ev.data.path)
      assert.equals("modify", ev.data.operation)
      assert.equals(sha256.hex(original), ev.data.old_hash)
      assert.equals(sha256.hex(disk_content), ev.data.new_hash)
      assert.equals(disk_content, ev.data.new_content)
      assert.equals(#disk_content, ev.data.new_content_size)

      -- reset AFTER emit
      assert.equals(disk_content, ec.get_content())
      assert.equals(sha256.hex(disk_content), ec.hash())
    end)

    it("clean modify: on-disk content matches expected -> no emit, no reset needed", function()
      local reg = registry_mod.new({ "a.py" })
      local content = "unchanged\n"
      reg.get_or_create("a.py", content)

      local abs_path = dir .. "/a.py"
      write_file(abs_path, content)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        get_now = function() return 0 end,
      }))

      watch.handle_path_event("a.py", abs_path)

      assert.equals(0, #events)
    end)
  end)

  describe("handle_path_event — tolerance window", function()
    it("a save within tolerance_ms is skipped; the same change past the window IS reported", function()
      local reg = registry_mod.new({ "a.py" })
      local original = "before\n"
      reg.get_or_create("a.py", original)

      local abs_path = dir .. "/a.py"
      local disk_content = "after\n"
      write_file(abs_path, disk_content)

      local now = 1000
      local recent_saves = { ["a.py"] = 1000 } -- editor "just saved" at t=1000
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        recent_saves = recent_saves,
        get_now = function() return now end,
        tolerance_ms = 250,
      }))

      now = 1100 -- 100ms later: still within the 250ms tolerance window
      watch.handle_path_event("a.py", abs_path)
      assert.equals(0, #events)

      now = 1300 -- 300ms after the save: past the tolerance window
      watch.handle_path_event("a.py", abs_path)
      assert.equals(1, #events)
      assert.equals("modify", events[1].data.operation)
    end)
  end)

  describe("handle_path_event — create", function()
    it("a watched file appearing on disk: operation=create, old_hash empty, registry seeded", function()
      local reg = registry_mod.new({ "new.py" })
      local abs_path = dir .. "/new.py"
      local content = "brand new file\n"
      write_file(abs_path, content)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        get_now = function() return 0 end,
      }))

      watch.handle_path_event("new.py", abs_path)

      assert.equals(1, #events)
      local ev = events[1]
      assert.equals("create", ev.data.operation)
      assert.equals("", ev.data.old_hash)
      assert.equals(sha256.hex(content), ev.data.new_hash)
      assert.equals(content, ev.data.new_content)
      assert.equals(#content, ev.data.new_content_size)

      local ec = reg.get("new.py")
      assert.is_not_nil(ec)
      assert.equals(content, ec.get_content())
    end)

    it("a file appearing that is NOT in files_under_review (not is_watched) -> skip", function()
      local reg = registry_mod.new({}) -- nothing watched
      local abs_path = dir .. "/stray.py"
      write_file(abs_path, "unwatched content\n")

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        get_now = function() return 0 end,
      }))

      watch.handle_path_event("stray.py", abs_path)

      assert.equals(0, #events)
      assert.is_nil(reg.get("stray.py"))
    end)
  end)

  describe("handle_path_event — delete", function()
    it("a tracked file disappearing: operation=delete, new_hash empty, no content fields, registry cleared", function()
      local reg = registry_mod.new({ "gone.py" })
      local prior_content = "will be deleted\n"
      local ec = reg.get_or_create("gone.py", prior_content)

      local abs_path = dir .. "/gone.py"
      write_file(abs_path, prior_content)
      delete_file(abs_path)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        get_now = function() return 0 end,
      }))

      watch.handle_path_event("gone.py", abs_path)

      assert.equals(1, #events)
      local ev = events[1]
      assert.equals("delete", ev.data.operation)
      assert.equals(sha256.hex(prior_content), ec.hash()) -- sanity: the ec object itself is unaffected by registry.delete
      assert.equals(sha256.hex(prior_content), ev.data.old_hash)
      assert.equals("", ev.data.new_hash)
      assert.is_nil(ev.data.new_content)
      assert.is_nil(ev.data.new_content_size)
      assert.is_nil(ev.data.new_content_head)
      assert.is_nil(ev.data.new_content_tail)

      assert.is_nil(reg.get("gone.py"))
    end)

    it("a never-known watched path disappearing (no registry entry): emits ONE operation=delete with old_hash empty", function()
      local reg = registry_mod.new({ "never-existed.py" })
      local abs_path = dir .. "/never-existed.py"
      -- never written, so fs_stat already reports non-existence

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        get_now = function() return 0 end,
      }))

      assert.has_no.errors(function()
        watch.handle_path_event("never-existed.py", abs_path)
      end)

      assert.equals(1, #events)
      local ev = events[1]
      assert.equals("fs.external_change", ev.kind)
      assert.equals("delete", ev.data.operation)
      assert.equals("never-existed.py", ev.data.path)
      assert.equals("", ev.data.old_hash)
      assert.equals("", ev.data.new_hash)
      assert.is_nil(ev.data.new_content)
      assert.is_nil(ev.data.new_content_size)
      assert.is_nil(ev.data.new_content_head)
      assert.is_nil(ev.data.new_content_tail)

      assert.is_nil(reg.get("never-existed.py"))
    end)
  end)

  describe("handle_path_event — explanation tagging", function()
    it("a fresh tagger mark surfaces as data.explanation on a modify", function()
      local reg = registry_mod.new({ "a.py" })
      reg.get_or_create("a.py", "old\n")

      local abs_path = dir .. "/a.py"
      write_file(abs_path, "new from git\n")

      local now = 0
      local tagger = tagger_mod.new({ get_now = function() return now end })
      tagger.mark_git()

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        files_under_review = {},
        emit = emit,
        tagger = tagger,
        get_now = function() return now end,
      }))

      watch.handle_path_event("a.py", abs_path)

      assert.equals(1, #events)
      assert.equals("git", events[1].data.explanation)
    end)
  end)

  -------------------------------------------------------------------------
  -- (B) The real vim.uv.new_fs_poll() seam — one integration test.
  -------------------------------------------------------------------------

  it("integration: a real external write to a watched file fires the watcher and emits a modify", function()
    local reg = registry_mod.new({ "watched.py" })
    local original = "original content\n"
    reg.get_or_create("watched.py", original)

    local abs_path = dir .. "/watched.py"
    write_file(abs_path, original)

    local events, emit = new_emit()
    local watch = track(fs_watcher.start({
      registry = reg,
      workspace = dir,
      files_under_review = { "watched.py" },
      emit = emit,
      poll_interval_ms = 100, -- fast poll to keep the test snappy
    }))

    -- vim.uv's fs_poll seeds its baseline stat via an ASYNC threadpool
    -- call made when :start() runs, not a synchronous one — so without a
    -- settle wait here, a write landing too soon after start() can race
    -- ahead of that baseline stat and get captured AS the baseline itself
    -- (silently swallowing this one transition; a real subsequent change
    -- would still be detected normally). Under light load this race rarely
    -- loses, but it flakes under the concurrent I/O load of the full test
    -- suite. Waiting here is a TEST-ONLY synchronization concern, not a
    -- production one: fs_watcher.start() itself makes no such promise, and
    -- doesn't need to.
    vim.wait(200)

    -- External write, outside any editor save path.
    write_file(abs_path, "changed externally\n")

    local ok = vim.wait(3000, function() return #events > 0 end, 50)

    assert.is_true(ok, "expected the fs_poll watcher to fire a modify within 3s")
    assert.equals(1, #events)
    assert.equals("fs.external_change", events[1].kind)
    assert.equals("modify", events[1].data.operation)
    assert.equals("watched.py", events[1].data.path)

    -- dispose(): further external writes must NOT emit (watchers stopped),
    -- and headless must exit clean afterward (no leaked handle).
    watch.dispose()
    write_file(abs_path, "changed again after dispose\n")
    vim.wait(300) -- give any (nonexistent) pending poll a chance to misfire
    assert.equals(1, #events)
  end)

  it("dispose() is idempotent and safe with zero watched files", function()
    local reg = registry_mod.new({})
    local events, emit = new_emit()
    local watch = fs_watcher.start({
      registry = reg,
      workspace = dir,
      files_under_review = {},
      emit = emit,
    })

    assert.has_no.errors(function() watch.dispose() end)
    assert.has_no.errors(function() watch.dispose() end)
  end)
end)
