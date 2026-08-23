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

--- Build a ResolvedScope-shaped table with defaults, mirroring
--- expected_content_registry_spec.lua's own helper.
local function scope(over)
  over = over or {}
  return {
    track = over.track or {},
    ignore = over.ignore or {},
    attachments = over.attachments or {},
  }
end

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
      local reg = registry_mod.new(scope({ track = { "a.py" } }))
      local original = "print('hello')\n"
      local ec = reg.get_or_create("a.py", original)

      local abs_path = dir .. "/a.py"
      local disk_content = "print('overwritten externally')\n"
      write_file(abs_path, disk_content)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope(),
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
      local reg = registry_mod.new(scope({ track = { "a.py" } }))
      local content = "unchanged\n"
      reg.get_or_create("a.py", content)

      local abs_path = dir .. "/a.py"
      write_file(abs_path, content)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope(),
        emit = emit,
        get_now = function() return 0 end,
      }))

      watch.handle_path_event("a.py", abs_path)

      assert.equals(0, #events)
    end)
  end)

  describe("handle_path_event — tolerance window", function()
    it("a save within tolerance_ms is skipped; the same change past the window IS reported", function()
      local reg = registry_mod.new(scope({ track = { "a.py" } }))
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
        scope = scope(),
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
      local reg = registry_mod.new(scope({ track = { "new.py" } }))
      local abs_path = dir .. "/new.py"
      local content = "brand new file\n"
      write_file(abs_path, content)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope(),
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
      local reg = registry_mod.new(scope()) -- nothing watched
      local abs_path = dir .. "/stray.py"
      write_file(abs_path, "unwatched content\n")

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope(),
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
      local reg = registry_mod.new(scope({ track = { "gone.py" } }))
      local prior_content = "will be deleted\n"
      local ec = reg.get_or_create("gone.py", prior_content)

      local abs_path = dir .. "/gone.py"
      write_file(abs_path, prior_content)
      delete_file(abs_path)

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope(),
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
      local reg = registry_mod.new(scope({ track = { "never-existed.py" } }))
      local abs_path = dir .. "/never-existed.py"
      -- never written, so fs_stat already reports non-existence

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope(),
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
      local reg = registry_mod.new(scope({ track = { "a.py" } }))
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
        scope = scope(),
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
    local reg = registry_mod.new(scope({ track = { "watched.py" } }))
    local original = "original content\n"
    reg.get_or_create("watched.py", original)

    local abs_path = dir .. "/watched.py"
    write_file(abs_path, original)

    local events, emit = new_emit()
    local watch = track(fs_watcher.start({
      registry = reg,
      workspace = dir,
      scope = scope({ track = { "watched.py" } }),
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
    local reg = registry_mod.new(scope())
    local events, emit = new_emit()
    local watch = fs_watcher.start({
      registry = reg,
      workspace = dir,
      scope = scope(),
      emit = emit,
    })

    assert.has_no.errors(function() watch.dispose() end)
    assert.has_no.errors(function() watch.dispose() end)
  end)

  -------------------------------------------------------------------------
  -- Rule entries (path-scope-provnvim.md §4.1): fs_event for discovery,
  -- fs_poll for change detection, directory-watcher-count bounding.
  -------------------------------------------------------------------------

  describe("rule entries — the editor's watcher is a coarse pre-filter only", function()
    it("a path that resolves to ignored emits NOTHING, even handed to handle_path_event directly", function()
      -- Drives handle_path_event directly (deterministic, per this file's own
      -- convention): the registry's is_watched consults resolve_path_role,
      -- so an ignored path is refused admission regardless of how it arrived.
      local reg = registry_mod.new(scope({ track = { "src/" }, ignore = { "*.class" } }))
      local abs_path = dir .. "/src/A.class"
      vim.fn.mkdir(dir .. "/src", "p")
      write_file(abs_path, "not a source file\n")

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "src/" }, ignore = { "*.class" } }),
        emit = emit,
        get_now = function() return 0 end,
      }))

      watch.handle_path_event("src/A.class", abs_path)

      assert.equals(0, #events)
      assert.is_nil(reg.get("src/A.class"))
    end)

    it("a file matching a folder rule for the first time is admitted and emits a create (live membership)", function()
      -- The file is written AFTER start(), so the initial seed walk never
      -- sees it — this is "created mid-session", not "pre-existing", and
      -- must go through the CREATE (not silent-seed) admission path.
      local reg = registry_mod.new(scope({ track = { "src/" } }))
      vim.fn.mkdir(dir .. "/src", "p")
      local abs_path = dir .. "/src/New.java"

      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "src/" } }),
        emit = emit,
        get_now = function() return 0 end,
      }))

      write_file(abs_path, "class New {}\n")
      watch.handle_path_event("src/New.java", abs_path)

      assert.equals(1, #events)
      assert.equals("create", events[1].data.operation)
      assert.equals("src/New.java", events[1].data.path)
      assert.is_not_nil(reg.get("src/New.java"))
    end)
  end)

  describe("rule entries — directory watcher bounding", function()
    it("an all-exact scope opens ZERO directory watchers", function()
      write_file(dir .. "/a.py", "x\n")
      local reg = registry_mod.new(scope({ track = { "a.py" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "a.py" } }),
        emit = emit,
      }))

      assert.equals(0, watch._dir_watcher_count())
    end)

    it("a folder rule opens directory watchers only under that prefix, and seeds pre-existing files silently", function()
      vim.fn.mkdir(dir .. "/src/sub", "p")
      vim.fn.mkdir(dir .. "/other", "p")
      write_file(dir .. "/a.txt", "root file\n")
      write_file(dir .. "/src/B.java", "class B {}\n")
      write_file(dir .. "/src/sub/C.java", "class C {}\n")
      write_file(dir .. "/other/d.txt", "unrelated\n")

      local reg = registry_mod.new(scope({ track = { "src/" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "src/" } }),
        emit = emit,
      }))

      -- "src" and "src/sub" — never the workspace root, never "other".
      assert.equals(2, watch._dir_watcher_count())

      -- Pre-existing files under the rule are seeded SILENTLY: admitted to
      -- the registry (so the cap accounting is honest) but with no
      -- synthetic fs.external_change — they were not "created" by anything
      -- this session observed.
      assert.equals(0, #events)
      assert.is_not_nil(reg.get("src/B.java"))
      assert.is_not_nil(reg.get("src/sub/C.java"))
      assert.is_nil(reg.get("a.txt"))
      assert.is_nil(reg.get("other/d.txt"))
    end)

    it("a suffix rule opens directory watchers for the whole tree", function()
      vim.fn.mkdir(dir .. "/src/sub", "p")
      vim.fn.mkdir(dir .. "/other", "p")
      write_file(dir .. "/Top.java", "class Top {}\n")
      write_file(dir .. "/src/B.java", "class B {}\n")
      write_file(dir .. "/src/sub/C.java", "class C {}\n")
      write_file(dir .. "/other/D.java", "class D {}\n")
      write_file(dir .. "/other/readme.txt", "not java\n")

      local reg = registry_mod.new(scope({ track = { "*.java" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "*.java" } }),
        emit = emit,
      }))

      -- workspace root + "src" + "src/sub" + "other" = 4.
      assert.equals(4, watch._dir_watcher_count())

      assert.equals(0, #events) -- pre-existing: seeded silently, nothing emitted
      assert.is_not_nil(reg.get("Top.java"))
      assert.is_not_nil(reg.get("src/B.java"))
      assert.is_not_nil(reg.get("src/sub/C.java"))
      assert.is_not_nil(reg.get("other/D.java"))
      assert.is_nil(reg.get("other/readme.txt"))
    end)

    it("hard-excluded directories never get a directory watcher, even under a whole-tree suffix rule", function()
      vim.fn.mkdir(dir .. "/.git/objects", "p")
      vim.fn.mkdir(dir .. "/.provenance", "p")
      vim.fn.mkdir(dir .. "/src", "p")
      write_file(dir .. "/.git/objects/pack.txt", "x\n")
      write_file(dir .. "/.provenance/manifest.json", "{}\n")
      write_file(dir .. "/src/A.java", "class A {}\n")

      local reg = registry_mod.new(scope({ track = { "*.java" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "*.java" } }),
        emit = emit,
      }))

      -- workspace root + "src" only — never ".git", ".git/objects", or
      -- ".provenance" (which would be a feedback loop: this session's own
      -- writer appends to .provenance/, and a watcher on it would fire on
      -- its own log being written).
      assert.equals(2, watch._dir_watcher_count())
      assert.is_not_nil(reg.get("src/A.java"))
    end)
  end)

  it("INTEGRATION: a real fs_event-discovered file under a folder rule is watched and emits a create", function()
    vim.fn.mkdir(dir .. "/src", "p")

    local reg = registry_mod.new(scope({ track = { "src/" } }))
    local events, emit = new_emit()
    local watch = track(fs_watcher.start({
      registry = reg,
      workspace = dir,
      scope = scope({ track = { "src/" } }),
      emit = emit,
      poll_interval_ms = 100, -- fast poll to keep the test snappy
    }))

    -- vim.uv's fs_event registers its watch with the OS (kqueue/FSEvents on
    -- macOS) via an ASYNC path, not a synchronous one — start() returning
    -- is not proof the OS has actually begun watching yet. A write landing
    -- before that registration truly lands is invisible to this watch
    -- FOREVER, not merely delayed (confirmed empirically: instrumented runs
    -- under `make test`'s full-suite load — every spec file spawned as a
    -- parallel headless nvim subprocess, uncapped — showed this assertion
    -- exhausting a 45s budget with the predicate never once turning true,
    -- while a settle wait here made every sampled round trip resolve in
    -- under 10ms even under that same load). Same category of race as the
    -- fs_poll baseline race documented on the sibling integration test
    -- above; this is the fs_event analogue of it.
    --
    -- TEST-ONLY synchronization concern. The FOREVER above is true of one
    -- fs_event HANDLE in isolation, NOT of the recorder. In production
    -- start() does a one-time initial workspace walk, and every callback
    -- re-scans its directory and diffs against last-known children rather
    -- than trusting the callback's own filename/events (which macOS reports
    -- unreliably anyway). So a file missed during the registration window is
    -- picked up by the NEXT event in that directory — delayed, not lost.
    -- This test is the only context where FOREVER is actually reachable,
    -- because it is the only one that creates a single file and then does
    -- nothing else. That is why fs_watcher.start() makes no readiness
    -- promise and does not need one: do NOT add a readiness handshake to
    -- production on the strength of this comment.
    vim.wait(300)

    -- A GENUINELY NEW file, created after the watcher started — the
    -- directory fs_event handle must discover it, admit it to the
    -- registry, and emit exactly one create.
    write_file(dir .. "/src/New.java", "class New {}\n")

    -- Poll-until-deadline, not a fixed sleep — the predicate short-circuits
    -- as soon as the event lands, so this costs nothing when idle. 5s is
    -- generous margin over the sub-10ms deliveries measured above once the
    -- settle wait removes the registration race.
    local ok = vim.wait(5000, function() return #events > 0 end, 50)

    assert.is_true(ok, "expected the fs_event-discovered file to emit within 5s")
    assert.equals(1, #events)
    assert.equals("fs.external_change", events[1].kind)
    assert.equals("create", events[1].data.operation)
    assert.equals("src/New.java", events[1].data.path)
    assert.is_not_nil(reg.get("src/New.java"))

    -- dispose() closes every handle (poll AND fs_event); headless must exit
    -- clean afterward (no leaked libuv handle).
    watch.dispose()
  end)

  -------------------------------------------------------------------------
  -- A folder root absent at session start (path-scope design spec D3):
  -- pre-fix, a `src/` scope entry that does not exist on disk at start()
  -- has NO handle anywhere reaching it -- its later creation, and
  -- everything inside it, goes unwatched for the whole session, silently.
  -- See fs_watcher.lua's own top-of-file docstring section "A folder root
  -- that does not exist yet at session start" for the fix.
  -------------------------------------------------------------------------

  --- Every "create" op emitted so far, in order, as {path, ...} entries --
  --- shared helper for the delete+recreate test below, which cares about
  --- creates specifically and does not want to assume a fixed total event
  --- count (a delete for the wiped file may also land in between).
  --- @param evs table
  --- @return string[]
  local function created_paths(evs)
    local out = {}
    for _, e in ipairs(evs) do
      if e.data.operation == "create" then
        table.insert(out, e.data.path)
      end
    end
    return out
  end

  describe("a folder root that does not exist yet at session start", function()
    it("DEFECT: src/ created mid-session (it did not exist at start()) is still discovered", function()
      -- No "src/" on disk at start() -- exactly the defect this fix closes.
      -- Proven to fail against the pre-fix module: reverting fs_watcher.lua
      -- to its state before this fix (`git show <pre-fix-rev>:lua/....lua`)
      -- and running only this test times out waiting for `ok`, because
      -- nothing ever opens a handle anywhere under a directory that was
      -- absent when start() ran -- there is no parent watcher reaching that
      -- far for a walk ROOT specifically (see the pre-fix comment this fix
      -- replaces, which named this exact gap as a known, unaddressed
      -- limitation).
      local reg = registry_mod.new(scope({ track = { "src/" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "src/" } }),
        emit = emit,
        poll_interval_ms = 100,
      }))

      -- start() opens the ancestor pursuit fs_event handle (on the
      -- workspace root, since "src" doesn't exist yet) — same async OS
      -- registration race as the sibling INTEGRATION test above: a change
      -- landing before that registration truly takes effect is invisible
      -- to this watch forever, not merely delayed. See that test's own
      -- comment for the empirical evidence.
      vim.wait(300)

      vim.fn.mkdir(dir .. "/src", "p")
      write_file(dir .. "/src/Main.java", "class Main {}\n")

      -- ONE combined, generous wait rather than bisecting the budget
      -- between "src/ promoted" and "Main.java discovered": promotion's
      -- own visit_dir call does a fresh scandir of "src" as its first act,
      -- so it picks up Main.java even if the write landed before promotion
      -- noticed the directory — splitting the wait would only make the
      -- test more sensitive to relative timing, not less. Poll-until-
      -- deadline, not a fixed sleep — costs nothing when idle. 8s keeps
      -- the sibling tests' 2x-of-single-round-trip relationship now that
      -- the registration race (the actual full-suite flake cause, not
      -- generic slowness) is handled by the settle wait above.
      local ok = vim.wait(8000, function() return #events > 0 end, 50)

      assert.is_true(ok, "expected src/Main.java to be discovered after src/ was created mid-session")
      assert.equals(1, #events)
      assert.equals("fs.external_change", events[1].kind)
      assert.equals("create", events[1].data.operation)
      assert.equals("src/Main.java", events[1].data.path)
      assert.is_not_nil(reg.get("src/Main.java"))

      watch.dispose()
    end)

    it("promotes through a folder root several levels deep, created in one batched mkdir -p", function()
      -- `mkdir -p a/b/c` in one call: the OS may coalesce this into a
      -- single fs_event notification at the workspace root, or fire
      -- several -- pursue() must re-derive progress from disk state every
      -- time, not assume a fixed notification count or order.
      local reg = registry_mod.new(scope({ track = { "a/b/c/" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "a/b/c/" } }),
        emit = emit,
        poll_interval_ms = 100,
      }))

      -- Same async watch-registration race as the sibling pursuit tests
      -- above — see the INTEGRATION test's comment for the empirical
      -- evidence this is a real (test-only) race, not generic slowness.
      vim.wait(300)

      vim.fn.mkdir(dir .. "/a/b/c", "p")
      write_file(dir .. "/a/b/c/Deep.java", "class Deep {}\n")

      -- Poll-until-deadline; short-circuits immediately once the event
      -- lands, so this costs nothing when idle.
      local ok = vim.wait(5000, function() return #events > 0 end, 50)

      assert.is_true(ok, "expected promotion through a/b/c despite the batched mkdir -p")
      assert.equals(1, #events)
      assert.equals("create", events[1].data.operation)
      assert.equals("a/b/c/Deep.java", events[1].data.path)
      assert.is_not_nil(reg.get("a/b/c/Deep.java"))

      watch.dispose()
    end)

    it("keeps working after the promoted directory is deleted and recreated (retains the ancestor pursuit handle)", function()
      local reg = registry_mod.new(scope({ track = { "src/" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "src/" } }),
        emit = emit,
        poll_interval_ms = 100,
      }))

      -- Same async watch-registration race as the sibling pursuit tests
      -- above — see the INTEGRATION test's comment for the empirical
      -- evidence this is a real (test-only) race, not generic slowness.
      vim.wait(300)

      vim.fn.mkdir(dir .. "/src", "p")
      write_file(dir .. "/src/First.java", "class First {}\n")

      -- Poll-until-deadline; short-circuits immediately once the event
      -- lands, so this costs nothing when idle.
      local ok1 = vim.wait(5000, function() return #created_paths(events) >= 1 end, 50)
      assert.is_true(ok1, "sanity: the initial promotion + create fired")
      assert.same({ "src/First.java" }, created_paths(events))

      -- rm -rf src && recreate, e.g. `git checkout src` or a build step
      -- that wipes and regenerates -- a different file this time, so the
      -- assertion below cannot be satisfied by the (harmless, still-alive)
      -- fs_poll handle left over from the first file alone. This also
      -- doubles as the settle for the FRESH fs_event handle pursue()
      -- opens on "src" when it re-promotes below (same registration race
      -- as above) — 600ms covers both purposes.
      vim.fn.delete(dir .. "/src", "rf")
      vim.wait(600)

      vim.fn.mkdir(dir .. "/src", "p")
      write_file(dir .. "/src/Second.java", "class Second {}\n")

      local ok2 = vim.wait(5000, function()
        for _, p in ipairs(created_paths(events)) do
          if p == "src/Second.java" then
            return true
          end
        end
        return false
      end, 50)

      assert.is_true(ok2, "expected detection to keep working after src/ was deleted and recreated")
      local creates = created_paths(events)
      assert.equals(2, #creates)
      assert.equals("src/First.java", creates[1])
      assert.equals("src/Second.java", creates[2])

      watch.dispose()
    end)

    it("dispose() closes a still-pending pursuit handle (target folder never appeared) without error", function()
      local reg = registry_mod.new(scope({ track = { "never/appears/" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "never/appears/" } }),
        emit = emit,
      }))

      -- One pursuit handle, on the workspace root, waiting for "never" to
      -- appear -- it never will in this test.
      assert.equals(1, watch._dir_watcher_count())

      assert.has_no.errors(function() watch.dispose() end)
      assert.has_no.errors(function() watch.dispose() end) -- idempotent
    end)

    it("an exact entry naming a not-yet-created file still opens ZERO directory watchers (pursuit never triggers for exact entries)", function()
      local reg = registry_mod.new(scope({ track = { "not_yet.py" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "not_yet.py" } }),
        emit = emit,
      }))

      assert.equals(0, watch._dir_watcher_count())
    end)

    it("a folder entry that resolves into a hard-excluded directory opens no handle there", function()
      local reg = registry_mod.new(scope({ track = { ".provenance/" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { ".provenance/" } }),
        emit = emit,
      }))

      assert.equals(0, watch._dir_watcher_count())
    end)

    it("a nested hard-excluded folder entry (a/.git/) opens no handle there either", function()
      vim.fn.mkdir(dir .. "/a", "p")
      local reg = registry_mod.new(scope({ track = { "a/.git/" } }))
      local events, emit = new_emit()
      local watch = track(fs_watcher.start({
        registry = reg,
        workspace = dir,
        scope = scope({ track = { "a/.git/" } }),
        emit = emit,
      }))

      assert.equals(0, watch._dir_watcher_count())
    end)
  end)
end)
