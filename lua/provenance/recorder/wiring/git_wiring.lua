--- git_wiring: the Neovim seam between a workspace's git repo and
--- `git.event` (Plan 7, Task 6). Detects a git repo in the workspace on
--- start and, when present, watches for HEAD movement (commit, checkout,
--- branch switch, merge, rebase, reset, amend) and emits a coarse
--- `state_change` `git.event`, while also marking the Plan 5 explanation
--- tagger so a file change that follows a git operation within the
--- tagger's window gets `explanation="git"` instead of surfacing as an
--- unexplained external change.
---
--- WHY THE REFLOG, NOT `.git/HEAD`: a plain `git commit` on the CURRENT
--- branch does NOT rewrite `.git/HEAD` — that file stays
--- `ref: refs/heads/<branch>` across the commit; only the branch ref
--- (`.git/refs/heads/<branch>`) and the reflog (`.git/logs/HEAD`) change.
--- `.git/HEAD` itself only changes on a branch switch / checkout / detached
--- HEAD move. Since same-branch commit is the single most common git
--- operation, watching `.git/HEAD` would silently miss it. `.git/logs/HEAD`
--- (the reflog) instead APPENDS one line on every HEAD movement, including
--- same-branch commits, resets, merges, rebases, and amends — so its
--- size/mtime changes exactly when we need to know HEAD moved. This module
--- watches the reflog file.
---
--- GRACEFUL DEGRADATION IS THE PRIMARY GATE (CLAUDE.md, task brief): no git
--- repo in the workspace, or no `git` binary on PATH at all, must NEVER
--- crash — `start()` returns an inert no-op handle instead. This mirrors
--- the git-wiring-degrades-gracefully rule for this whole plugin: missing
--- git integration is a degraded signal, not a failure.
---
--- TESTABILITY-FIRST SPLIT (mirrors fs_watcher.lua): `handle._on_head_change()`
--- is a deterministic decision handler — read the current commit sha via the
--- injectable `run_git` seam, build+emit the payload, mark the tagger — with
--- no waiting involved. Tests drive it directly. A thin `vim.uv` watcher
--- seam wires reflog change notifications to it.
---
--- WATCHER CHOICE: `vim.uv.new_fs_poll()` on the resolved `.git/logs/HEAD`
--- reflog path, same rationale as fs_watcher.lua (stat-based polling
--- survives rename-into-place writes and git's own atomic ref updates, and
--- is easy to reason about/test relative to native fs_event notification
--- quirks). `.git/logs/HEAD` only exists once there has been at least one
--- ref update, so a brand-new repo with zero commits may not have it yet
--- (or the git dir can't be resolved at all — a layout this port doesn't
--- special-case). Either case degrades to a `run_git`-driven poll timer
--- that only fires `_on_head_change()` when the observed HEAD sha actually
--- changes since the last tick — never a crash, just a coarser signal, and
--- it still catches that first commit.
---
--- COMMIT_SHA HANDLING (documented choice — task brief flagged this as an
--- either-or): when `rev-parse HEAD` fails (unborn branch, detached-HEAD
--- edge cases, a transient git error), this module still EMITS a
--- `state_change` `git.event` with `commit_sha` omitted, rather than
--- swallowing the event entirely. The state change itself (a HEAD-file
--- write happened) is still real and still worth recording — and still
--- worth marking the tagger for, since a file change genuinely may follow
--- (e.g. `git checkout` on an unborn branch can still touch tracked files).
--- `commit_sha` is documented as optional in the payload
--- (`git_payloads.build_git_event`), so an event without it is a valid,
--- format-compatible shape.
---
--- ## THE COMMIT GRAPH (program spec S5)
---
--- `git.event` also carries `sha`, `parents[]` and `branch`, so replay can
--- show real branch and merge structure. Gradescope delivers the working
--- tree only, never `.git`, and a `.git` that did travel would be
--- rewritable after the fact (`amend`, `rebase`, `filter-branch`) — so the
--- graph is captured HERE, at record time, inside the signed hash chain.
--- The payload rules (the order of `parents` is meaningful; `[]` ≠ absent;
--- `commit_sha` is still emitted alongside `sha`) live in `git_payloads.lua`
--- and are pinned by `tests/conformance/fixtures/git-event.json`.
---
--- Three reads, all through the one injectable `run_git` seam:
---   `rev-parse HEAD`                    -> sha / commit_sha  (pre-existing)
---   `rev-list --parents -n 1 <sha>`     -> parents           (new)
---   `symbolic-ref --quiet --short HEAD` -> branch            (new)
--- `symbolic-ref` failing IS the detached-HEAD signal, so `branch` is
--- omitted rather than invented. `rev-list` is asked only when there is a
--- sha to describe, and its answer is accepted only if its first token is
--- that same sha — otherwise `parents` is omitted, because "could not read"
--- must never be reported as `[]` ("root commit").
---
--- NO GIT AUTHOR IDENTITY reaches the log — not a name, not an email, not
--- an author date, not a commit message. That is a protocol constraint (the
--- approved CPHS protocol 2026-06-19796 treats a new category of identifier
--- as requiring a filed modification BEFORE implementation), enforced here
--- by two things: the only commit projection available is
--- `git_payloads.commit_view(sha, parents)`, which has no parameter an
--- author field could enter through; and every value this module lifts out
--- of git's stdout must first pass `is_single_token` / `is_object_id` below,
--- so an author-shaped line (`Name <a@b.example> 1700000000 +0000`) is
--- rejected outright instead of landing in `sha`, `parents`, or `branch`.
--- Note this tightens the pre-existing `commit_sha` read too: it used to
--- take `rev-parse`'s stdout verbatim. See the IRB tests in
--- tests/recorder/wiring/git_wiring_spec.lua and
--- tests/recorder/events/git_payloads_spec.lua.
---
--- ## WHY EMISSION STAYS SYNCHRONOUS (unlike provcode/provjet)
---
--- The other two recorders had to make emission asynchronous, because their
--- host APIs expose parents only through a call that is async (VS Code) or
--- must not run on the UI thread (JetBrains) — and they then each needed a
--- serializing queue so a fast graph read could not overtake a slow one and
--- write log entries out of order. This port needs none of that and
--- deliberately does not add it: reading the graph is two more `run_git`
--- calls inside the SAME synchronous `_on_head_change` handler that already
--- read `rev-parse HEAD`, so `emit` is still called exactly once, from
--- straight-line code, with no yield between the session host reading and
--- advancing `prev_hash`/`seq`. That atomicity is what stops a concurrent
--- emitter from manufacturing a tamper finding against an innocent student;
--- introducing an await here to mirror the other ports would reintroduce
--- precisely the race they had to engineer around.
---
--- Cost of the two extra invocations: `_on_head_change` runs only from an
--- fs_poll / timer callback (default every 2000 ms) and only when the reflog
--- actually moved — never from a buffer callback, never on the keystroke
--- path. It reuses the existing `vim.fn.system` seam rather than adding a
--- new blocking mechanism.
---
--- NO CAPTURE-POLICY GATE HERE. `git.event` is a FLOOR event kind: it has
--- no key in `policy.capture`, so "off" is not expressible, and adding
--- fields to a floor payload does not make it gateable. That is deliberate
--- — the commit graph is the EXCULPATORY evidence that a large insert was a
--- merge or a checkout rather than a paste. It also matters mechanically:
--- suppression must happen before an entry is chained and given a `seq`
--- (see session/policy_gate.lua), because a `seq` hole reads to validation
--- check 4 (`seq_gaps`) as a deleted entry — which would turn a course's
--- privacy setting into a tamper signal against the student.
---
--- Composes (does not reimplement): recorder.events.git_payloads
--- (commit_view, build_git_event), recorder.events.explanation_tags
--- (tagger.mark_git()).
local git_payloads = require("provenance.recorder.events.git_payloads")

local M = {}

-- Single module-level libuv handle, reused everywhere the module needs
-- vim.uv (or the legacy vim.loop alias on older Neovim builds).
local uv = vim.uv or vim.loop

local DEFAULT_POLL_INTERVAL_MS = 2000

--- Build the default `run_git` seam: run git in `workspace` via
--- `vim.fn.system`, reporting success via `vim.v.shell_error`. Wrapped in
--- pcall so a missing `git` binary (or any other vim.fn.system failure)
--- degrades to `{ok=false}` rather than throwing — this is the seam that
--- lets "no git installed" degrade exactly like "no repo present".
--- @param workspace string
--- @return function(args_list: string[]) -> { ok: boolean, out: string }
local function make_default_run_git(workspace)
  return function(args_list)
    local ok, result = pcall(function()
      local cmd = vim.list_extend({ "git", "-C", workspace }, args_list or {})
      local out = vim.fn.system(cmd)
      local shell_error = vim.v.shell_error
      return { ok = shell_error == 0, out = vim.trim(out or "") }
    end)
    if not ok then
      return { ok = false, out = "" }
    end
    return result
  end
end

--- Safely invoke an (possibly injected, possibly throwing) run_git seam.
--- Never throws. Returns a well-shaped {ok, out} table even on failure.
--- @param run_git function
--- @param args_list string[]
--- @return table { ok: boolean, out: string }
local function safe_run_git(run_git, args_list)
  local ok, result = pcall(run_git, args_list)
  if ok and type(result) == "table" then
    return { ok = result.ok == true, out = result.out or "" }
  end
  return { ok = false, out = "" }
end

--- Is `s` a single bare token — non-empty, no whitespace, no ASCII control
--- characters? This is the floor every value lifted out of git's stdout has
--- to clear before it can enter a signed payload.
---
--- It is deliberately looser than "looks like a sha" (an object id can be 40
--- or 64 hex depending on the repo's hash algorithm, and abbreviations exist)
--- and deliberately strict about whitespace, which is what makes it
--- load-bearing for the no-author-identity constraint: every shape author
--- identity arrives in — `Real Name <a@b.example>`, a reflog line, a
--- `git log` line — contains a space. Git's own ref-name rules forbid
--- whitespace and control characters in a branch name too, so nothing
--- legitimate is lost.
--- @param s any
--- @return boolean
local function is_single_token(s)
  if type(s) ~= "string" or s == "" then
    return false
  end
  return s:match("^[^%s%c]+$") ~= nil
end

--- Is `s` plausibly a git object id — a single token of at least 7 hex
--- digits? Applied to PARENT shas only, where we are parsing a multi-token
--- line and need to know we parsed the right thing.
--- @param s any
--- @return boolean
local function is_object_id(s)
  if not is_single_token(s) then
    return false
  end
  return #s >= 7 and s:match("^%x+$") ~= nil
end

--- read_parents(run_git, sha) -> string[]|nil
---
--- Parent object ids of `sha`, in GIT'S OWN ORDER — `[1]` is the branch that
--- was merged into. `git rev-list --parents -n 1 <sha>` prints one line:
--- `<sha> <parent1> <parent2> ...`, so a root commit yields a line with a
--- single token, which is how `{}` ("genuinely no parents") is distinguished
--- from nil ("could not read").
---
--- Returns nil — never `{}` — on every failure, because `{}` is a positive
--- claim of "root commit" that a failed read is not entitled to make. The
--- line is accepted only when its first token is the very sha we asked
--- about and every remaining token is an object id; anything else (a git
--- error printed to stdout, an injected seam answering something unrelated,
--- an author-bearing line) is a read we did not understand.
--- @param run_git function
--- @param sha string
--- @return string[]|nil
local function read_parents(run_git, sha)
  local r = safe_run_git(run_git, { "rev-list", "--parents", "-n", "1", sha })
  if not r.ok or r.out == "" then
    return nil
  end

  -- One commit was requested, so one line is expected. More than one line
  -- means we are not reading what we think we are reading.
  if r.out:find("[\r\n]") ~= nil then
    return nil
  end

  local tokens = vim.split(vim.trim(r.out), "%s+", { trimempty = true })
  if #tokens == 0 or tokens[1] ~= sha then
    return nil
  end

  local parents = {}
  for i = 2, #tokens do
    if not is_object_id(tokens[i]) then
      return nil
    end
    -- NEVER sorted: the first parent is the branch merged INTO, so order is
    -- meaning, and JCS leaves array elements alone.
    parents[i - 1] = tokens[i]
  end
  return parents
end

--- read_branch(run_git) -> string|nil
---
--- The current branch name, or nil when HEAD is detached. `git symbolic-ref
--- --quiet --short HEAD` exits non-zero exactly when HEAD is not a symbolic
--- ref, which IS the detached-HEAD signal — so a failure omits the key
--- rather than inventing `"HEAD"` or `""`. An omitted branch and a branch
--- literally named "HEAD" are different claims.
---
--- Note this succeeds on an unborn branch (a fresh `git init`, where
--- `rev-parse HEAD` fails): the branch exists even though no commit does, so
--- `branch` without `sha` is a correct payload, not a contradiction.
--- @param run_git function
--- @return string|nil
local function read_branch(run_git)
  local r = safe_run_git(run_git, { "symbolic-ref", "--quiet", "--short", "HEAD" })
  if not r.ok then
    return nil
  end
  local name = vim.trim(r.out or "")
  if not is_single_token(name) then
    return nil
  end
  return name
end

--- detect_repo(workspace, run_git) -> boolean
---
--- A workspace is a git repo if `.git` exists (directory for a normal repo,
--- file for a worktree/submodule) OR `git rev-parse --git-dir` succeeds
--- (covers layouts where `.git` isn't a direct child, e.g. `GIT_DIR`/
--- `core.worktree` overrides). Never throws.
--- @param workspace string
--- @param run_git function
--- @return boolean
local function detect_repo(workspace, run_git)
  local ok, stat = pcall(uv.fs_stat, workspace .. "/.git")
  if ok and stat ~= nil then
    return true
  end
  local r = safe_run_git(run_git, { "rev-parse", "--git-dir" })
  return r.ok
end

--- Best-effort read of a `.git` FILE's `gitdir: <path>` pointer (the
--- worktree/submodule layout). Never throws; returns nil on any failure.
--- @param git_file_path string
--- @return string|nil gitdir
local function read_gitdir_pointer(git_file_path)
  local ok, content = pcall(function()
    local fd = uv.fs_open(git_file_path, "r", 438) -- 438 = 0o666
    if not fd then
      return nil
    end
    local data
    local read_ok = pcall(function()
      local st = uv.fs_fstat(fd)
      if st then
        data = uv.fs_read(fd, st.size, 0)
      end
    end)
    uv.fs_close(fd)
    if not read_ok then
      return nil
    end
    return data
  end)
  if not ok or type(content) ~= "string" then
    return nil
  end
  local gitdir = content:match("gitdir:%s*(.-)%s*[\r\n]") or content:match("gitdir:%s*(.-)%s*$")
  if gitdir == nil or gitdir == "" then
    return nil
  end
  return gitdir
end

--- resolve_git_dir(workspace, run_git) -> string|nil
---
--- Resolve the actual git DIRECTORY (not a specific file inside it) for
--- this workspace. Normal repo: `.git` directly under the workspace.
--- Worktree/submodule (`.git` is a file): best-effort read its
--- `gitdir: <path>` pointer; falls back to `git rev-parse --git-dir` if
--- the pointer can't be read. Returns nil (defensive degrade — no crash)
--- if none of these resolve. Callers append the specific file they want
--- to watch (e.g. `/logs/HEAD` for the reflog).
--- @param workspace string
--- @param run_git function
--- @return string|nil
local function resolve_git_dir(workspace, run_git)
  local git_path = workspace .. "/.git"
  local ok, stat = pcall(uv.fs_stat, git_path)
  if ok and stat ~= nil then
    if stat.type == "directory" then
      return git_path
    elseif stat.type == "file" then
      local gitdir = read_gitdir_pointer(git_path)
      if gitdir ~= nil then
        if not gitdir:match("^/") then
          gitdir = workspace .. "/" .. gitdir
        end
        return gitdir
      end
    end
  end

  local r = safe_run_git(run_git, { "rev-parse", "--git-dir" })
  if r.ok and r.out ~= "" then
    local git_dir = r.out
    if not git_dir:match("^/") then
      git_dir = workspace .. "/" .. git_dir
    end
    return git_dir
  end

  return nil
end

--- start(opts) -> handle
--- @param opts table {
---   workspace: string             -- absolute workspace dir
---   emit: function(kind, data)    -- SessionHost.emit
---   tagger: table|nil             -- ExplanationTagger (tagger.mark_git()); may be nil
---   run_git: function(args_list: string[]) -> {ok, out}|nil -- injectable; default shells out
---   poll_interval_ms: number|nil, default 2000
--- }
--- @return table handle {
---   dispose(): idempotent teardown,
---   _on_head_change(): deterministic decision handler, exposed for tests,
---   active: boolean -- whether a repo was detected
---   _watch_path: string|nil -- resolved reflog path being fs_polled, when
---     the primary watch path could be set up; nil when the fallback
---     run_git poll timer is in use instead. Test-oriented introspection.
--- }
function M.start(opts)
  opts = opts or {}

  local workspace = opts.workspace
  local emit = opts.emit
  local tagger = opts.tagger
  local poll_interval_ms = opts.poll_interval_ms or DEFAULT_POLL_INTERVAL_MS
  local run_git = opts.run_git or make_default_run_git(workspace)

  -- Repo detection itself must never crash — a bogus workspace path or a
  -- throwing injected run_git both degrade to "not a repo" rather than
  -- propagating into whatever called start().
  local detect_ok, is_repo = pcall(detect_repo, workspace, run_git)
  is_repo = detect_ok and is_repo or false

  if not is_repo then
    if vim.g.provenance_debug then
      vim.notify(
        string.format("Provenance: git wiring — no git repo detected at %s", tostring(workspace)),
        vim.log.levels.DEBUG
      )
    end
    return {
      dispose = function() end,
      _on_head_change = function() end,
      active = false,
    }
  end

  local disposed = false
  local watcher = nil -- either a uv fs_poll or a uv timer, both stop()/close()

  local handle = { active = true }

  --- Deterministic decision handler: read the current HEAD commit sha and
  --- its graph position (parents, branch), build+emit a state_change
  --- git.event, mark the tagger. Guarded end to end (pcall) so any
  --- run_git/tagger failure degrades to a silent no-op rather than
  --- propagating into an fs_poll/timer callback.
  ---
  --- Straight-line and fully SYNCHRONOUS on purpose: `emit` is called
  --- exactly once, with nothing between the session host reading and
  --- advancing `prev_hash`/`seq`. See the module docstring on why this port
  --- does not need (and must not grow) the serializing queue provcode and
  --- provjet required.
  function handle._on_head_change()
    if disposed then
      return
    end
    pcall(function()
      local r = safe_run_git(run_git, { "rev-parse", "HEAD" })
      local out = (r.ok and r.out ~= "") and r.out or nil
      -- Tightened alongside S5: a bare token only. `rev-parse` printing
      -- anything multi-token means we did not read a sha, and this is the
      -- one place git stdout could otherwise reach a signed payload
      -- verbatim.
      local commit_sha = is_single_token(out) and out or nil

      -- The graph read is skipped when there is no commit to describe (a
      -- fresh `git init`): there is nothing to ask about, and `parents`
      -- must stay ABSENT rather than become `[]`.
      local view = nil
      if commit_sha ~= nil then
        -- commit_view is the ONLY projection of a commit this plugin has,
        -- and takes exactly (sha, parents) — no author field can enter here.
        view = git_payloads.commit_view(commit_sha, read_parents(run_git, commit_sha))
      end

      local branch = read_branch(run_git)

      -- `commit_sha` and `sha` carry the same value on purpose: 1.x readers
      -- only know the former, and 1.x support is permanent (program spec §9).
      local ev = git_payloads.build_git_event("state_change", commit_sha, view, branch)
      emit(ev.kind, ev.data)

      if tagger then
        tagger.mark_git()
      end
    end)
  end

  -------------------------------------------------------------------------
  -- Watch: prefer an fs_poll directly on the resolved REFLOG file
  -- (`.git/logs/HEAD`), which appends on every HEAD movement including a
  -- same-branch commit (fires only on an actual change, mirrors
  -- fs_watcher.lua). If the git dir can't be resolved, or the reflog
  -- doesn't exist yet (a fresh repo with zero commits), degrade to a
  -- run_git-driven poll timer that only fires _on_head_change() when the
  -- observed sha differs from the prior tick -- this also catches that
  -- first commit, before any reflog exists.
  -------------------------------------------------------------------------

  local resolve_ok, git_dir = pcall(resolve_git_dir, workspace, run_git)
  git_dir = (resolve_ok and type(git_dir) == "string") and git_dir or nil

  local reflog_path = nil
  if git_dir then
    local candidate = git_dir .. "/logs/HEAD"
    local stat_ok, stat = pcall(uv.fs_stat, candidate)
    if stat_ok and stat ~= nil then
      reflog_path = candidate
    end
  end

  handle._watch_path = nil

  if reflog_path then
    local poll = uv.new_fs_poll()
    if poll then
      local started = poll:start(reflog_path, poll_interval_ms, function(_err, _prev, _curr)
        if disposed then
          return
        end
        vim.schedule(function()
          if disposed then
            return
          end
          pcall(handle._on_head_change)
        end)
      end)
      if started then
        watcher = poll
        handle._watch_path = reflog_path
      else
        pcall(function() poll:close() end)
      end
    end
  end

  if watcher == nil then
    -- Defensive fallback: no reflog could be resolved (a fresh repo with
    -- no commits yet, or an unusual git dir layout), so poll `run_git` on
    -- a timer instead of a file watcher. Only calls _on_head_change() when
    -- the observed sha actually changes, so this doesn't spam an event
    -- every tick.
    local last_sha = nil
    local timer = uv.new_timer()
    if timer then
      local timer_ok = pcall(function()
        timer:start(poll_interval_ms, poll_interval_ms, function()
          if disposed then
            return
          end
          vim.schedule(function()
            if disposed then
              return
            end
            pcall(function()
              local r = safe_run_git(run_git, { "rev-parse", "HEAD" })
              local sha = (r.ok and r.out ~= "") and r.out or nil
              if sha ~= last_sha then
                last_sha = sha
                handle._on_head_change()
              end
            end)
          end)
        end)
      end)
      if timer_ok then
        watcher = timer
      else
        pcall(function() timer:close() end)
      end
    end
  end

  --- Idempotent: stops+closes the watcher (fs_poll or fallback timer) so no
  --- libuv handle leaks (a leaked handle keeps headless Neovim from
  --- exiting), and makes _on_head_change() a no-op afterward.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true

    if watcher then
      pcall(function()
        watcher:stop()
        watcher:close()
      end)
      watcher = nil
    end
  end

  return handle
end

return M
