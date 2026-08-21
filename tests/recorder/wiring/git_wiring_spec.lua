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
    -- The base mock answers `rev-parse HEAD` with the caller's result and
    -- reports "nothing readable" for the two S5 commit-graph reads
    -- (`rev-list --parents` and `symbolic-ref`), so the pre-S5 cases below go
    -- on asserting exactly what they always asserted. Cases that DO want a
    -- graph pass `graph`.
    local function make_run_git(head_result, graph)
      graph = graph or {}
      return function(args)
        if args[1] == "rev-parse" and args[2] == "HEAD" then
          return head_result
        end
        if args[1] == "rev-list" then
          return graph.rev_list or { ok = false, out = "" }
        end
        if args[1] == "symbolic-ref" then
          return graph.symbolic_ref or { ok = false, out = "" }
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

-- ---------------------------------------------------------------------------
-- S5: the commit graph (sha / parents / branch).
--
-- Byte-level parity with provcode and provjet lives in the shared vector
-- (tests/conformance/fixtures/git-event.json, consumed by conformance_spec).
-- What is tested here is the WIRING: which git commands are run, how their
-- output is turned into a payload, and — load-bearing — what it refuses.
-- ---------------------------------------------------------------------------

describe("git_wiring: commit graph (program spec S5)", function()
  local SHA = ("a"):rep(40)
  local P1 = ("b"):rep(40)
  local P2 = ("c"):rep(40)

  local dir
  local handles

  before_each(function()
    dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir .. "/.git", "p")
    handles = {}
  end)

  after_each(function()
    for _, h in ipairs(handles) do
      pcall(h.dispose)
    end
    handles = {}
    pcall(vim.fn.delete, dir, "rf")
  end)

  --- Drive one HEAD change with a scripted git and return the emitted payload
  --- plus the argv of every git invocation, in order.
  --- @param script table { head, rev_list, symbolic_ref } — each a run_git result
  local function emit_once(script)
    local events = {}
    local calls = {}
    local handle = git_wiring.start({
      workspace = dir,
      emit = function(kind, data)
        table.insert(events, { kind = kind, data = data })
      end,
      run_git = function(args)
        table.insert(calls, table.concat(args, " "))
        if args[1] == "rev-parse" and args[2] == "HEAD" then
          return script.head or { ok = false, out = "" }
        end
        if args[1] == "rev-list" then
          return script.rev_list or { ok = false, out = "" }
        end
        if args[1] == "symbolic-ref" then
          return script.symbolic_ref or { ok = false, out = "" }
        end
        return { ok = true, out = ".git" }
      end,
    })
    table.insert(handles, handle)
    assert.is_true(handle.active)
    handle._on_head_change()
    assert.equals(1, #events)
    assert.equals("git.event", events[1].kind)
    return events[1].data, calls
  end

  local function key_set(t)
    local keys = {}
    for k in pairs(t) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    return keys
  end

  it("an ordinary commit on a branch emits operation, commit_sha, sha, parents and branch", function()
    local data = emit_once({
      head = { ok = true, out = SHA },
      rev_list = { ok = true, out = SHA .. " " .. P1 },
      symbolic_ref = { ok = true, out = "main" },
    })
    assert.same({ "branch", "commit_sha", "operation", "parents", "sha" }, key_set(data))
    assert.equals("state_change", data.operation)
    assert.equals(SHA, data.commit_sha)
    assert.equals(SHA, data.sha) -- same value under both keys: 1.x readers know only commit_sha
    assert.same({ P1 }, { data.parents[1] })
    assert.equals(1, #data.parents)
    assert.equals("main", data.branch)
  end)

  it("a merge keeps git's parent ORDER — parents[1] is the branch merged INTO", function()
    local data = emit_once({
      head = { ok = true, out = SHA },
      rev_list = { ok = true, out = SHA .. " " .. P2 .. " " .. P1 },
      symbolic_ref = { ok = true, out = "main" },
    })
    assert.equals(2, #data.parents)
    assert.equals(P2, data.parents[1])
    assert.equals(P1, data.parents[2])
  end)

  it("a root commit yields parents = [] (an empty JSON ARRAY, not an object)", function()
    local data = emit_once({
      head = { ok = true, out = SHA },
      rev_list = { ok = true, out = SHA },
      symbolic_ref = { ok = true, out = "main" },
    })
    assert.is_not_nil(data.parents)
    assert.equals(0, #data.parents)
    assert.is_true(require("provenance.core.json").is_array(data.parents))
    assert.is_true(require("provenance.core.json").canonicalize(data):find('"parents":[]', 1, true) ~= nil)
  end)

  it("MANDATORY: an unreadable graph OMITS parents — 'could not read' is never reported as 'root commit'", function()
    -- `[]` is a positive claim. A failed, empty, multi-line, or mismatched
    -- rev-list must all omit the key instead, or every transient git hiccup
    -- would be logged as a root commit.
    for _, rev_list in ipairs({
      { ok = false, out = "" },
      { ok = true, out = "" },
      { ok = true, out = "fatal: bad object HEAD" },
      { ok = true, out = ("d"):rep(40) .. " " .. P1 }, -- a line about a DIFFERENT commit
      { ok = true, out = SHA .. " " .. P1 .. "\n" .. P2 .. " " .. P1 }, -- more than one commit
      { ok = true, out = SHA .. " not-a-sha" },
    }) do
      local data = emit_once({
        head = { ok = true, out = SHA },
        rev_list = rev_list,
        symbolic_ref = { ok = true, out = "main" },
      })
      assert.is_nil(data.parents, "unreadable graph must omit parents, got " .. vim.inspect(data.parents))
      assert.equals(SHA, data.sha) -- the rest of the event is still recorded
    end
  end)

  it("a detached HEAD OMITS branch — never invents \"HEAD\" or \"\"", function()
    -- `symbolic-ref` exiting non-zero IS the detached-HEAD signal.
    local data = emit_once({
      head = { ok = true, out = SHA },
      rev_list = { ok = true, out = SHA .. " " .. P1 },
      symbolic_ref = { ok = false, out = "" },
    })
    assert.same({ "commit_sha", "operation", "parents", "sha" }, key_set(data))
    assert.is_nil(data.branch)
  end)

  it("a branch name with slashes and dashes survives verbatim", function()
    local data = emit_once({
      head = { ok = true, out = SHA },
      rev_list = { ok = true, out = SHA },
      symbolic_ref = { ok = true, out = "feat/proj2-part1\n" },
    })
    assert.equals("feat/proj2-part1", data.branch)
  end)

  it("a non-ASCII branch name survives verbatim (it is a VALUE, never an object key)", function()
    local data = emit_once({
      head = { ok = true, out = SHA },
      rev_list = { ok = true, out = SHA },
      symbolic_ref = { ok = true, out = "feature/\195\188ber" },
    })
    assert.equals("feature/\195\188ber", data.branch)
    -- The signed bytes still order keys the fixed ASCII way, whatever the branch.
    local canonical = require("provenance.core.json").canonicalize(data)
    assert.equals(1, canonical:find('{"branch":', 1, true))
  end)

  it("no sha to describe (a fresh `git init`) skips the graph read entirely but still records the branch", function()
    local data, calls = emit_once({
      head = { ok = false, out = "" },
      symbolic_ref = { ok = true, out = "main" },
    })
    assert.same({ "branch", "operation" }, key_set(data))
    for _, argv in ipairs(calls) do
      assert.is_nil(argv:find("rev-list", 1, true), "must not ask for the graph of a commit that does not exist")
    end
  end)

  it("runs the graph reads on the SAME synchronous handler — emit is called once, with no deferral", function()
    -- provcode and provjet had to make emission async and add a serializing
    -- queue; this port must not. `emit` is called exactly once from
    -- straight-line code, so nothing can interleave between the session host
    -- reading and advancing prev_hash/seq — the property that stops a
    -- concurrent emitter from manufacturing a tamper finding.
    local order = {}
    local handle = git_wiring.start({
      workspace = dir,
      emit = function()
        table.insert(order, "emit")
      end,
      tagger = { mark_git = function() table.insert(order, "mark_git") end },
      run_git = function(args)
        table.insert(order, "git:" .. args[1])
        if args[1] == "rev-parse" and args[2] == "HEAD" then
          return { ok = true, out = SHA }
        end
        if args[1] == "rev-list" then
          return { ok = true, out = SHA .. " " .. P1 }
        end
        if args[1] == "symbolic-ref" then
          return { ok = true, out = "main" }
        end
        return { ok = true, out = ".git" }
      end,
    })
    table.insert(handles, handle)

    -- The D12 discriminator is derived ONCE at start() (writer rule 1), so its
    -- git invocations are already in `order` and are not part of what this case
    -- is about. Cleared, not filtered, so the assertion below still describes
    -- the handler EXACTLY — every call it makes, in sequence, and nothing else.
    -- That the derivation happens at setup and never here is asserted in
    -- "derived ONCE at setup, never per event" below.
    order = {}

    handle._on_head_change()

    -- Everything happened inside the call, in order, with exactly one emit.
    assert.same({ "git:rev-parse", "git:rev-list", "git:symbolic-ref", "emit", "mark_git" }, order)
  end)

  it("git.event carries no capture-policy gate: a suppressed event would burn a seq", function()
    -- git.event is a FLOOR kind (no key in policy.capture), so this wiring must
    -- not grow a gate of its own. Gating happens in session/policy_gate.lua,
    -- BEFORE an entry is chained and given a seq — a hole here would read to
    -- validation check 4 (seq_gaps) as a deleted entry, turning a course's
    -- privacy setting into a tamper signal against the student.
    local capture_policy = require("provenance.core.capture_policy")
    local all_off = capture_policy.resolve({
      capture = { selection_change = false, focus_change = false, terminal = false },
    })
    assert.is_true(capture_policy.is_event_kind_captured("git.event", all_off))

    -- ...and the wiring emits regardless of any policy it is never handed.
    local data = emit_once({
      head = { ok = true, out = SHA },
      rev_list = { ok = true, out = SHA },
      symbolic_ref = { ok = true, out = "main" },
    })
    assert.equals("state_change", data.operation)
  end)

  it("IRB (CPHS 2026-06-19796): NO git author name or email can reach a git.event payload", function()
    -- A PROTOCOL commitment, not a style preference: the approved CPHS protocol
    -- treats a new category of identifier as requiring a filed modification
    -- BEFORE implementation, and git author identity is exactly that. This
    -- recorder reads git through stdout, so the risk is concrete — the reflog
    -- lines this module watches, and `git log`'s default format, both carry
    -- `Name <email>`. Every value lifted out of stdout must therefore be a bare
    -- token, and author identity never is.
    local AUTHOR_LINE = "abc1234 Ada Lovelace <ada@berkeley.edu> 1700000000 +0000\tcommit: fix the thing"

    local events = {}
    local handle = git_wiring.start({
      workspace = dir,
      emit = function(kind, data)
        table.insert(events, { kind = kind, data = data })
      end,
      run_git = function(args)
        if args[1] == "rev-parse" and args[2] == "--git-dir" then
          return { ok = true, out = ".git" }
        end
        -- Every read answers with an author-bearing, reflog-shaped line.
        return { ok = true, out = AUTHOR_LINE }
      end,
    })
    table.insert(handles, handle)

    handle._on_head_change()
    assert.equals(1, #events)

    local data = events[1].data
    assert.same({ "operation" }, key_set(data))

    local serialized = require("provenance.core.json").canonicalize(data)
    for _, forbidden in ipairs({ "Ada", "Lovelace", "@", "berkeley", "commit: fix", "1700000000" }) do
      assert.is_nil(serialized:find(forbidden, 1, true),
        "git.event must never carry " .. forbidden .. "; got " .. serialized)
    end
  end)

  it("IRB: an author-shaped answer cannot become a branch name either", function()
    -- Called out separately because `branch` is the one field with no format
    -- constraint of its own, so it is the natural place for `Name <email>` to
    -- land. Git's ref-name rules forbid whitespace, so rejecting it costs
    -- nothing legitimate.
    for _, hostile in ipairs({
      "Ada Lovelace <ada@berkeley.edu>",
      "main\nada@berkeley.edu",
      "",
      "   ",
    }) do
      local data = emit_once({
        head = { ok = true, out = SHA },
        rev_list = { ok = true, out = SHA },
        symbolic_ref = { ok = true, out = hostile },
      })
      assert.is_nil(data.branch, "must reject branch " .. vim.inspect(hostile))
    end
  end)

  it("IRB: an author-shaped answer cannot become a sha either", function()
    -- This tightens the pre-existing commit_sha read, which used to take
    -- `rev-parse`'s stdout verbatim.
    local data = emit_once({
      head = { ok = true, out = "abc1234 Ada Lovelace <ada@berkeley.edu>" },
      symbolic_ref = { ok = true, out = "main" },
    })
    assert.is_nil(data.commit_sha)
    assert.is_nil(data.sha)
    assert.equals("main", data.branch)
  end)
end)

-- ---------------------------------------------------------------------------
-- D12 — the repository discriminator, as WIRED.
--
-- root_commit_sha_spec.lua covers the derivation rules. These cases cover the
-- three things only the wiring can get wrong: deriving ONCE instead of per
-- event, labelling the wrong repository, and letting a value the reader would
-- reject reach a payload anyway.
-- ---------------------------------------------------------------------------

describe("git_wiring: the repository discriminator (decision D12)", function()
  local SHA = ("a"):rep(40)
  local P1 = ("b"):rep(40)
  local ROOT = ("9"):rep(40)

  local dir
  local handles

  before_each(function()
    dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir .. "/.git", "p")
    handles = {}
  end)

  after_each(function()
    for _, h in ipairs(handles) do
      pcall(h.dispose)
    end
    handles = {}
    pcall(vim.fn.delete, dir, "rf")
  end)

  --- Start a handle with a scripted git. `overrides` maps a joined argv to a
  --- run_git result; anything unlisted falls back to the sane defaults below.
  --- Returns the handle, the emitted events, and the argv log.
  local function start(overrides)
    local events, calls = {}, {}
    local defaults = {
      ["rev-parse HEAD"] = { ok = true, out = SHA },
      ["rev-list --parents -n 1 " .. SHA] = { ok = true, out = SHA .. " " .. P1 },
      ["symbolic-ref --quiet --short HEAD"] = { ok = true, out = "main" },
      ["rev-parse --is-shallow-repository"] = { ok = true, out = "false" },
      ["rev-list --max-parents=0 --first-parent HEAD"] = { ok = true, out = ROOT },
      ["rev-parse --git-dir"] = { ok = true, out = ".git" },
    }
    local handle = git_wiring.start({
      workspace = dir,
      emit = function(kind, data)
        table.insert(events, { kind = kind, data = data })
      end,
      run_git = function(args)
        local key = table.concat(args, " ")
        table.insert(calls, key)
        local answer = (overrides or {})[key]
        if answer ~= nil then
          return answer
        end
        return defaults[key] or { ok = false, out = "" }
      end,
    })
    table.insert(handles, handle)
    return handle, events, calls
  end

  local function count(calls, needle)
    local n = 0
    for _, c in ipairs(calls) do
      if c == needle then
        n = n + 1
      end
    end
    return n
  end

  it("labels every git.event that carries a sha", function()
    local handle, events = start()
    handle._on_head_change()
    assert.equals(1, #events)
    assert.equals(ROOT, events[1].data.root_commit_sha)
    -- `state_change`, not `commit`: writer rule 10 rides the field on every
    -- observation carrying a sha, because an unlabelled one does not correlate
    -- even when its neighbours in the same session do.
    assert.equals("state_change", events[1].data.operation)
  end)

  it("WRITER RULE 1: derived ONCE at setup, never per event", function()
    -- Two subprocess spawns at wiring setup are fine. Two per HEAD movement are
    -- not: `_on_head_change` runs from an fs_poll callback, and the value
    -- cannot change for the life of a repository anyway.
    local handle, events, calls = start()
    local after_setup_shallow = count(calls, "rev-parse --is-shallow-repository")
    local after_setup_roots = count(calls, "rev-list --max-parents=0 --first-parent HEAD")
    assert.equals(1, after_setup_shallow)
    assert.equals(1, after_setup_roots)

    for _ = 1, 5 do
      handle._on_head_change()
    end

    assert.equals(after_setup_shallow, count(calls, "rev-parse --is-shallow-repository"))
    assert.equals(after_setup_roots, count(calls, "rev-list --max-parents=0 --first-parent HEAD"))
    assert.equals(5, #events)
    for _, e in ipairs(events) do
      assert.equals(ROOT, e.data.root_commit_sha)
    end
  end)

  it("WRITER RULE 9: the label comes from the SAME seam that read the sha", function()
    -- One value per repository OBSERVED. This port watches exactly one
    -- repository and resolves both the label and the sha through one
    -- `git -C <workspace>`, so a workspace that IS a submodule is labelled with
    -- the submodule's own root — never an outer repository's.
    --
    -- Driven as the failure it prevents: a seam representing a SUBMODULE, whose
    -- root differs from the outer repository's. The emitted label must be the
    -- submodule's. A wiring that reached past its seam for an "outer" value
    -- would re-create the exact sha-space merge the field exists to prevent.
    local SUBMODULE_ROOT = ("1"):rep(40)
    local handle, events = start({
      ["rev-list --max-parents=0 --first-parent HEAD"] = { ok = true, out = SUBMODULE_ROOT },
    })
    handle._on_head_change()
    assert.equals(SUBMODULE_ROOT, events[1].data.root_commit_sha)
    assert.are_not.equals(ROOT, events[1].data.root_commit_sha)

    -- ...and two handles on two different seams get two different labels,
    -- rather than one of them adopting the other's.
    local other_dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(other_dir .. "/.git", "p")
    local other_events = {}
    local other = git_wiring.start({
      workspace = other_dir,
      emit = function(kind, data)
        table.insert(other_events, { kind = kind, data = data })
      end,
      run_git = function(args)
        local key = table.concat(args, " ")
        if key == "rev-parse HEAD" then
          return { ok = true, out = SHA }
        elseif key == "rev-parse --is-shallow-repository" then
          return { ok = true, out = "false" }
        elseif key == "rev-list --max-parents=0 --first-parent HEAD" then
          return { ok = true, out = ROOT }
        end
        return { ok = false, out = "" }
      end,
    })
    table.insert(handles, other)
    other._on_head_change()
    assert.equals(ROOT, other_events[1].data.root_commit_sha)
    assert.are_not.equals(
      other_events[1].data.root_commit_sha,
      events[1].data.root_commit_sha
    )
    pcall(vim.fn.delete, other_dir, "rf")
  end)

  it("OMITS — never nulls — on a shallow clone", function()
    local handle, events = start({
      ["rev-parse --is-shallow-repository"] = { ok = true, out = "true" },
    })
    handle._on_head_change()
    -- Absent, and absent means the key is not in the table at all. In Lua a
    -- table cannot hold nil, so `is_nil` here IS the omission assertion — but
    -- the canonical bytes are what actually matter, and the conformance suite
    -- pins those against the vector's absent case.
    assert.is_nil(events[1].data.root_commit_sha)
    assert.same({ "branch", "commit_sha", "operation", "parents", "sha" }, (function()
      local keys = {}
      for k in pairs(events[1].data) do
        keys[#keys + 1] = k
      end
      table.sort(keys)
      return keys
    end)())
  end)

  it("OMITS on any derivation failure, and still emits the event", function()
    -- Witnessing the repository is optional; recording is not. Every failure
    -- costs the label and nothing else.
    for _, override in ipairs({
      { ["rev-parse --is-shallow-repository"] = { ok = false, out = "" } },
      { ["rev-list --max-parents=0 --first-parent HEAD"] = { ok = false, out = "" } },
      { ["rev-list --max-parents=0 --first-parent HEAD"] = { ok = true, out = "" } },
      { ["rev-list --max-parents=0 --first-parent HEAD"] = { ok = true, out = "/Users/s/proj" } },
      { ["rev-list --max-parents=0 --first-parent HEAD"] = { ok = true, out = ("A"):rep(40) } },
    }) do
      local handle, events = start(override)
      handle._on_head_change()
      assert.equals(1, #events)
      assert.equals(SHA, events[1].data.sha)
      assert.is_nil(events[1].data.root_commit_sha)
    end
  end)

  it("a throwing run_git at setup degrades to an unlabelled, still-recording session", function()
    local events = {}
    local handle = git_wiring.start({
      workspace = dir,
      emit = function(kind, data)
        table.insert(events, { kind = kind, data = data })
      end,
      run_git = function(args)
        if args[1] == "rev-parse" and args[2] == "--is-shallow-repository" then
          error("boom")
        end
        if args[1] == "rev-parse" and args[2] == "HEAD" then
          return { ok = true, out = SHA }
        end
        return { ok = true, out = ".git" }
      end,
    })
    table.insert(handles, handle)
    assert.is_true(handle.active)
    assert.has_no.errors(function()
      handle._on_head_change()
    end)
    assert.equals(1, #events)
    assert.is_nil(events[1].data.root_commit_sha)
  end)

  it("a value the READER would reject never reaches a payload", function()
    -- Belt and braces: `root_commit_sha.derive` filters, and
    -- `build_git_event` re-checks through log-core's own reader. Driven here
    -- through the wiring so both gates are exercised end to end.
    local git_event = require("provenance.core.git_event")
    for _, bad in ipairs({
      "/Users/student/cs61b/proj2",
      "git@github.com:acme/proj.git",
      ("A"):rep(40),
      "9999999",
      "",
    }) do
      assert.is_false(git_event.is_usable_discriminator(bad))
      local handle, events = start({
        ["rev-list --max-parents=0 --first-parent HEAD"] = { ok = true, out = bad },
      })
      handle._on_head_change()
      assert.is_nil(events[1].data.root_commit_sha, "leaked: " .. bad)
    end
  end)

  it("a workspace with no repo derives nothing and spawns no git for it", function()
    local no_repo = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(no_repo, "p")
    local calls = {}
    local handle = git_wiring.start({
      workspace = no_repo,
      emit = function() end,
      run_git = function(args)
        table.insert(calls, table.concat(args, " "))
        return { ok = false, out = "" }
      end,
    })
    table.insert(handles, handle)
    assert.is_false(handle.active)
    assert.equals(0, count(calls, "rev-list --max-parents=0 --first-parent HEAD"))
    pcall(vim.fn.delete, no_repo, "rf")
  end)
end)
