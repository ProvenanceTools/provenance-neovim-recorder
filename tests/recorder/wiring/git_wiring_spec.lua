--- Tests for git_wiring (Plan 7, Task 6): the Neovim seam that detects a
--- git repo in the workspace and, when present, emits `git.event` on
--- HEAD/state changes and marks the Plan 5 explanation tagger. Graceful
--- degradation (no repo / no git binary -> no-op, never a crash) is the
--- primary gate here, so it gets the most coverage.
---
--- Most cases drive `handle._on_head_change()` directly — a deterministic
--- handler with no waiting involved — with an injected `run_git` seam, the
--- same testability-first split fs_watcher.lua uses for handle_path_event.
local git_wiring = require("provenance.recorder.wiring.git_wiring")
local tagger_mod = require("provenance.recorder.events.explanation_tags")

local function new_emit()
  local events = {}
  local function emit(kind, data)
    table.insert(events, { kind = kind, data = data })
  end
  return events, emit
end

describe("git_wiring", function()
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
  -- Repo absent — the key graceful-degradation gate.
  -------------------------------------------------------------------------

  describe("repo absent", function()
    it("injected run_git reporting no repo -> no-op handle: no events, active=false, safe _on_head_change, safe dispose", function()
      local events, emit = new_emit()
      local mark_called = false
      local fake_tagger = { mark_git = function() mark_called = true end }

      local handle = track(git_wiring.start({
        workspace = dir,
        emit = emit,
        tagger = fake_tagger,
        run_git = function() return { ok = false } end,
      }))

      assert.is_false(handle.active)
      assert.equals(0, #events)

      assert.has_no.errors(function() handle._on_head_change() end)
      assert.equals(0, #events)
      assert.is_false(mark_called)

      assert.has_no.errors(function() handle.dispose() end)
      assert.has_no.errors(function() handle.dispose() end) -- idempotent
    end)

    it("DEFAULT run_git in a real non-repo temp dir -> no-op, no crash (git binary present or absent)", function()
      local events, emit = new_emit()
      local handle

      assert.has_no.errors(function()
        handle = track(git_wiring.start({
          workspace = dir,
          emit = emit,
        }))
      end)

      assert.is_false(handle.active)
      assert.equals(0, #events)
      assert.has_no.errors(function() handle._on_head_change() end)
      assert.equals(0, #events)
      assert.has_no.errors(function() handle.dispose() end)
    end)

    it("nonexistent workspace path with default run_git -> no-op, no crash", function()
      local events, emit = new_emit()
      local handle

      assert.has_no.errors(function()
        handle = track(git_wiring.start({
          workspace = dir .. "/does-not-exist",
          emit = emit,
        }))
      end)

      assert.is_false(handle.active)
      assert.equals(0, #events)
      assert.has_no.errors(function() handle.dispose() end)
    end)
  end)

  -------------------------------------------------------------------------
  -- Repo present (injected run_git) — HEAD change emits + marks tagger.
  -------------------------------------------------------------------------

  describe("repo present", function()
    local function make_run_git(head_result)
      return function(args)
        if args[1] == "rev-parse" and args[2] == "HEAD" then
          return head_result
        end
        return { ok = true, out = ".git" }
      end
    end

    it("HEAD change emits ONE git.event(state_change, commit_sha) and marks the tagger", function()
      vim.fn.mkdir(dir .. "/.git", "p")

      local events, emit = new_emit()
      local now = 0
      local tagger = tagger_mod.new({ get_now = function() return now end })

      local handle = track(git_wiring.start({
        workspace = dir,
        emit = emit,
        tagger = tagger,
        run_git = make_run_git({ ok = true, out = "abc123def" }),
      }))

      assert.is_true(handle.active)
      assert.equals(0, #events)

      handle._on_head_change()

      assert.equals(1, #events)
      assert.equals("git.event", events[1].kind)
      assert.equals("state_change", events[1].data.operation)
      assert.equals("abc123def", events[1].data.commit_sha)

      -- tagger was marked: a subsequent consume() within the window reports "git"
      assert.equals("git", tagger.consume())
    end)

    it("commit_sha omitted when HEAD can't be read (unborn branch / rev-parse failure), still marks tagger", function()
      vim.fn.mkdir(dir .. "/.git", "p")

      local events, emit = new_emit()
      local mark_called = false
      local fake_tagger = { mark_git = function() mark_called = true end }

      local handle = track(git_wiring.start({
        workspace = dir,
        emit = emit,
        tagger = fake_tagger,
        run_git = make_run_git({ ok = false }),
      }))

      handle._on_head_change()

      assert.equals(1, #events)
      assert.equals("git.event", events[1].kind)
      assert.equals("state_change", events[1].data.operation)
      assert.is_nil(events[1].data.commit_sha)

      local has_commit_sha = false
      for k in pairs(events[1].data) do
        if k == "commit_sha" then
          has_commit_sha = true
        end
      end
      assert.is_false(has_commit_sha)
      assert.is_true(mark_called)
    end)

    it("tagger may be nil -- guarded, no error, event still emits", function()
      vim.fn.mkdir(dir .. "/.git", "p")
      local events, emit = new_emit()

      local handle = track(git_wiring.start({
        workspace = dir,
        emit = emit,
        tagger = nil,
        run_git = make_run_git({ ok = true, out = "deadbeef" }),
      }))

      assert.has_no.errors(function() handle._on_head_change() end)
      assert.equals(1, #events)
    end)

    it("a run_git that throws mid-callback -> no crash; treated like a failed rev-parse (event still emits, no commit_sha)", function()
      vim.fn.mkdir(dir .. "/.git", "p")
      local events, emit = new_emit()

      local handle = track(git_wiring.start({
        workspace = dir,
        emit = emit,
        run_git = function(args)
          if args[1] == "rev-parse" and args[2] == "HEAD" then
            error("simulated git failure")
          end
          return { ok = true, out = ".git" }
        end,
      }))

      assert.has_no.errors(function() handle._on_head_change() end)
      assert.equals(1, #events)
      assert.equals("state_change", events[1].data.operation)
      assert.is_nil(events[1].data.commit_sha)
    end)
  end)

  -------------------------------------------------------------------------
  -- Watch target — proves the fix: the reflog (`.git/logs/HEAD`), not
  -- `.git/HEAD`, is what gets watched, since a same-branch commit rewrites
  -- the reflog but leaves `.git/HEAD` untouched.
  -------------------------------------------------------------------------

  describe("watch target", function()
    it("with .git/logs/HEAD present, resolves+watches the REFLOG path, not .git/HEAD", function()
      vim.fn.mkdir(dir .. "/.git/logs", "p")
      local reflog_path = dir .. "/.git/logs/HEAD"
      vim.fn.writefile(
        { "0000000000000000000000000000000000000000 abc123def Author <a@example.com> 1700000000 +0000\tcommit (initial): init" },
        reflog_path
      )

      local events, emit = new_emit()

      local handle = track(git_wiring.start({
        workspace = dir,
        emit = emit,
        run_git = function(args)
          if args[1] == "rev-parse" and args[2] == "HEAD" then
            return { ok = true, out = "abc123def" }
          end
          return { ok = true, out = ".git" }
        end,
      }))

      assert.is_true(handle.active)
      assert.equals(vim.fs.normalize(reflog_path), vim.fs.normalize(handle._watch_path))
    end)

    it("with .git/logs/HEAD ABSENT (fresh repo, no commits), falls back to the run_git poll: still active, still detects a sha change", function()
      vim.fn.mkdir(dir .. "/.git", "p")
      -- No .git/logs directory at all — mirrors a just-`git init`ed repo
      -- before any commit has ever moved HEAD.

      local events, emit = new_emit()
      local mark_called = false
      local fake_tagger = { mark_git = function() mark_called = true end }

      local handle = track(git_wiring.start({
        workspace = dir,
        emit = emit,
        tagger = fake_tagger,
        run_git = function(args)
          if args[1] == "rev-parse" and args[2] == "HEAD" then
            return { ok = true, out = "freshsha1" }
          end
          return { ok = true, out = ".git" }
        end,
      }))

      assert.is_true(handle.active)
      assert.is_nil(handle._watch_path) -- no reflog to watch -> fallback in use

      -- The fallback poll timer degrades gracefully, but _on_head_change
      -- (the deterministic handler it drives) still works: the first
      -- commit is still detectable via the run_git-driven path.
      handle._on_head_change()

      assert.equals(1, #events)
      assert.equals("git.event", events[1].kind)
      assert.equals("state_change", events[1].data.operation)
      assert.equals("freshsha1", events[1].data.commit_sha)
      assert.is_true(mark_called)
    end)
  end)

  -------------------------------------------------------------------------
  -- dispose — idempotent, stops the watcher, no leaked handle.
  -------------------------------------------------------------------------

  describe("dispose", function()
    it("is idempotent; after dispose() _on_head_change() no-ops (no emit)", function()
      vim.fn.mkdir(dir .. "/.git", "p")
      local events, emit = new_emit()

      local handle = git_wiring.start({
        workspace = dir,
        emit = emit,
        run_git = function(args)
          if args[1] == "rev-parse" and args[2] == "HEAD" then
            return { ok = true, out = "abc123def" }
          end
          return { ok = true, out = ".git" }
        end,
      })

      assert.has_no.errors(function() handle.dispose() end)
      assert.has_no.errors(function() handle.dispose() end)

      handle._on_head_change()
      assert.equals(0, #events)
    end)

    it("no-op handle (repo absent) dispose is safe even without ever starting a watcher", function()
      local events, emit = new_emit()
      local handle = git_wiring.start({
        workspace = dir,
        emit = emit,
        run_git = function() return { ok = false } end,
      })

      assert.has_no.errors(function() handle.dispose() end)
    end)
  end)
end)
