--- fs_watcher — Path 2 of 3 external-change emission paths (docs/design.md
--- §4.5, recorder PRD §4.5): a `vim.uv` filesystem watcher over
--- `files_under_review`. Catches external writes/creates/deletes that
--- happen while Neovim is unfocused, or doesn't have the file open at all —
--- the path that fires PROMPTLY, unlike Neovim's lazy focus-based
--- `FileChangedShell` reload (which only fires on focus-gain / an explicit
--- `:checktime`). Path 1 (save-time hash check, `save_time_checker.lua`)
--- covers the complementary "editor has the file open and just wrote it"
--- case.
---
--- Faithful port of the monorepo's wiring/fs-watcher.ts. See its top-of-file
--- design-notes comment for the modify/create/delete rules; this module
--- mirrors them:
---   - MODIFY: skip if within `tolerance_ms` of the file's last editor save
---     (`recent_saves[rel]`, populated by Path 1 / the coordinator) — that
---     change is already captured via `doc.save`. Otherwise
---     `compare_saved_content` against the registry entry: `clean_save` ->
---     skip (no real change), `external_change` -> emit + `ec.reset`.
---   - CREATE: only for paths the registry `is_watched` (i.e. listed in
---     `files_under_review`) and with no existing registry entry — emit
---     `old_hash=""` + seed the registry so subsequent edits chain from
---     reality.
---   - DELETE: emit `new_hash=""` (no content fields) for ANY watched file
---     that disappeared, whether or not it was ever known to us — `old_hash`
---     is the registry's prior hash if we have one, `""` otherwise (matches
---     fs-watcher.ts's `onDidDelete`, which still reports a never-opened
---     file's deletion so the analyzer's timeline doesn't silently drop the
---     event). Then drop the registry entry (a harmless no-op if there
---     wasn't one) so a subsequent re-create starts clean.
---
--- TESTABILITY-FIRST SPLIT (real fs watchers are timing-flaky):
---   (A) `handle.handle_path_event(rel, abs_path)` — a deterministic
---       decision handler that reads current on-disk state + consults
---       `registry`/`recent_saves`, with no waiting involved. Tests drive
---       this directly for every create/modify/delete/skip case.
---   (B) A thin `vim.uv` watcher seam (one watcher per file in
---       `files_under_review`) that wires OS/poll notifications to (A).
---       Exercised by exactly one integration test using `vim.wait`.
---
--- WATCHER CHOICE: `vim.uv.new_fs_poll()`, not `new_fs_event()`. `fs_poll`
--- is stat-based (polls mtime/size/etc. at `poll_interval_ms`) rather than
--- relying on OS-native change notifications. That makes it: (1) reliable
--- across tools that save via rename-into-place (a common atomic-write
--- pattern some `fs_event` backends miss, since the watched inode gets
--- replaced rather than written-through), and (2) easy to test — its
--- firing cadence is a known, bounded interval rather than dependent on
--- OS-notification timing/coalescing quirks. The tradeoff is coarser
--- latency (bounded by `poll_interval_ms`, default 1000ms) versus
--- `fs_event`'s near-instant notification, which is acceptable here: this
--- path only needs to beat Neovim's LAZY focus-triggered reload (which can
--- be arbitrarily late), not be instantaneous.
---
--- KNOWN NUANCE: `uv_fs_poll` seeds its baseline stat via an async
--- threadpool call made when `:start()` runs, not a synchronous one. A
--- change landing in the narrow window before that baseline stat completes
--- can be captured AS the baseline itself, silently absorbing that one
--- transition. This is harmless in practice — the file's true state is
--- still whatever it is, and any subsequent change is detected normally on
--- the next poll — but it means "started watching, then changed
--- immediately" has no hard latency guarantee for that first transition.
---
--- Composes (does not reimplement): recorder.state.expected_content_registry,
--- recorder.events.external_change_detector (compare_saved_content),
--- recorder.events.external_change_content (build_external_change_content),
--- recorder.events.explanation_tags (tagger.consume()), core.sha256.
local external_change_detector = require("provenance.recorder.events.external_change_detector")
local external_change_content = require("provenance.recorder.events.external_change_content")
local sha256 = require("provenance.core.sha256")

local M = {}

-- Single module-level libuv handle, reused everywhere the module needs
-- vim.uv (or the legacy vim.loop alias on older Neovim builds).
local uv = vim.uv or vim.loop

local DEFAULT_TOLERANCE_MS = 250
local DEFAULT_POLL_INTERVAL_MS = 1000

--- Read a whole file's raw bytes via vim.uv. Never throws. Binary-safe (not
--- vim.fn.readfile, which splits on "\n" and mangles CRLF/CR line endings).
--- Exact idiom mirror of save_time_checker.lua's read_file_bytes.
--- @param path string
--- @return string|nil  file bytes, or nil if the file can't be read
local function read_file_bytes(path)
  local fd = uv.fs_open(path, "r", 438) -- 438 = 0o666
  if not fd then
    return nil
  end
  local ok, data = pcall(function()
    local st = uv.fs_fstat(fd)
    if not st then
      error("fstat failed")
    end
    local chunk = uv.fs_read(fd, st.size, 0)
    if chunk == nil then
      error("read failed")
    end
    return chunk
  end)
  uv.fs_close(fd) -- always close, on both the success and error paths
  if not ok then
    return nil
  end
  return data
end

local function default_get_now()
  return uv.hrtime() / 1e6
end

--- utf16-style diff_size for a "whole file appeared/disappeared" operation
--- (create's new content, or delete's prior content) — reuses
--- external_change_detector's private utf16-unit diff-size math by
--- comparing `content` against an empty baseline, rather than duplicating
--- that (unexported) helper here. Matches modify's diff_size convention
--- (utf16 code units, not bytes). Returns 0 for an empty/`""` content
--- (compare_saved_content short-circuits to `clean_save` in that case,
--- which carries no diff_size field — 0 is the correct value anyway).
--- @param content string
--- @return integer
local function whole_file_diff_size(content)
  local empty_ec = {
    hash = function() return sha256.hex("") end,
    get_content = function() return "" end,
  }
  local result = external_change_detector.compare_saved_content(empty_ec, content)
  if result.kind == "clean_save" then
    return 0
  end
  return result.diff_size
end

--- Fill the fs.external_change content fields (new_content_size + either
--- new_content or new_content_head/new_content_tail) onto `data` in place.
--- Shared by the create and modify branches (delete carries no content).
--- @param data table
--- @param content string
local function apply_content_fields(data, content)
  local fields = external_change_content.build_external_change_content(content)
  data.new_content_size = fields.new_content_size
  if fields.new_content ~= nil then
    data.new_content = fields.new_content
  else
    data.new_content_head = fields.new_content_head
    data.new_content_tail = fields.new_content_tail
  end
end

--- start(opts) -> handle
--- @param opts table {
---   registry: table              -- ExpectedContentRegistry
---   workspace: string             -- absolute workspace root
---   files_under_review: string[]  -- workspace-relative paths to watch
---   emit: function(kind, data)    -- SessionHost.emit
---   tagger: table|nil             -- ExplanationTagger (tagger.consume())
---   recent_saves: table|nil       -- shared rel -> timestamp_ms, updated by
---                                    the editor-save path; consulted (not
---                                    owned) here.
---   get_now: function()->number (ms)|nil, default vim.uv.hrtime()/1e6
---   tolerance_ms: number|nil, default 250
---   poll_interval_ms: number|nil, default 1000
--- }
--- @return table handle { handle_path_event(rel, abs_path), dispose() }
function M.start(opts)
  opts = opts or {}

  local registry = opts.registry
  local workspace = opts.workspace
  local files_under_review = opts.files_under_review or {}
  local emit = opts.emit
  local tagger = opts.tagger
  local recent_saves = opts.recent_saves or {}
  local get_now = opts.get_now or default_get_now
  local tolerance_ms = opts.tolerance_ms or DEFAULT_TOLERANCE_MS
  local poll_interval_ms = opts.poll_interval_ms or DEFAULT_POLL_INTERVAL_MS

  local disposed = false
  local watchers = {}

  local handle = {}

  -------------------------------------------------------------------------
  -- (A) Pure-ish decision handler — callable directly by tests.
  -------------------------------------------------------------------------

  --- handle_path_event(rel, abs_path)
  ---
  --- Given a path that MIGHT have changed on disk, decides
  --- create/modify/delete/skip against current on-disk state + the
  --- registry + recent_saves, and emits at most one fs.external_change.
  --- Never throws (I/O failures degrade to a silent no-op).
  --- @param rel string       workspace-relative path (registry key, payload path)
  --- @param abs_path string  absolute on-disk path to stat/read
  function handle.handle_path_event(rel, abs_path)
    -- 1. TOLERANCE SKIP: this change is the editor's own just-happened
    -- save, already captured by Path 1 / doc.save.
    local last_save = recent_saves[rel]
    if last_save ~= nil and (get_now() - last_save) < tolerance_ms then
      return
    end

    local stat = uv.fs_stat(abs_path)
    local exists = stat ~= nil and stat.type == "file"
    local ec = registry.get(rel)

    if not exists then
      -- DELETE. Emit for ANY watched file that disappeared, whether or not
      -- we ever knew its content: old_hash is the prior hash if `ec` is
      -- known, "" otherwise (matches fs-watcher.ts's onDidDelete, which
      -- reports even a never-opened file's deletion).
      local old_hash = ec and ec.hash() or ""
      local diff_size = ec and whole_file_diff_size(ec.get_content()) or 0

      local data = {
        path = rel,
        operation = "delete",
        old_hash = old_hash,
        new_hash = "",
        diff_size = diff_size,
      }
      local explanation = tagger and tagger.consume()
      if explanation ~= nil then
        data.explanation = explanation
      end

      emit("fs.external_change", data)

      -- Drop AFTER emitting: a subsequent re-create starts from a clean
      -- baseline. No-op (registry.delete is idempotent) if there was no
      -- entry to begin with.
      registry.delete(rel)
      return
    end

    -- exists: read on-disk bytes. A transient read failure (raced with a
    -- delete/rewrite between the stat and the read) is a silent no-op —
    -- the next poll tick will see whatever the file settled to.
    local content = read_file_bytes(abs_path)
    if content == nil then
      return
    end

    if ec == nil then
      -- CREATE: the file appeared on disk where nothing was tracked. Only
      -- report it for paths actually under review.
      if not registry.is_watched(rel) then
        return
      end

      local new_hash = sha256.hex(content)
      local data = {
        path = rel,
        operation = "create",
        old_hash = "",
        new_hash = new_hash,
        diff_size = whole_file_diff_size(content),
      }
      apply_content_fields(data, content)

      local explanation = tagger and tagger.consume()
      if explanation ~= nil then
        data.explanation = explanation
      end

      emit("fs.external_change", data)

      -- Seed AFTER emitting, so subsequent edits chain from reality.
      registry.get_or_create(rel, content)
      return
    end

    -- MODIFY.
    local result = external_change_detector.compare_saved_content(ec, content)
    if result.kind == "clean_save" then
      -- On-disk content matches what we expected — nothing to report.
      return
    end

    local data = {
      path = rel,
      operation = "modify",
      old_hash = result.old_hash,
      new_hash = result.new_hash,
      diff_size = result.diff_size,
    }
    apply_content_fields(data, content)

    local explanation = tagger and tagger.consume()
    if explanation ~= nil then
      data.explanation = explanation
    end

    emit("fs.external_change", data)

    -- Reset AFTER emitting, same rule as save_time_checker: subsequent
    -- tracked edits chain from disk reality.
    ec.reset(content)
  end

  -------------------------------------------------------------------------
  -- (B) Thin vim.uv watcher seam — one fs_poll per watched file.
  -------------------------------------------------------------------------

  for _, rel in ipairs(files_under_review) do
    local abs_path = workspace .. "/" .. rel
    local poll = uv.new_fs_poll()
    if poll then
      -- Never let a callback error propagate into libuv: schedule onto the
      -- main loop (fs_poll callbacks fire off the fast event path, where
      -- most nvim_* / vim.fn calls are disallowed) and pcall-guard.
      local ok = poll:start(abs_path, poll_interval_ms, function(_err, _prev, _curr)
        if disposed then
          return
        end
        vim.schedule(function()
          if disposed then
            return
          end
          pcall(handle.handle_path_event, rel, abs_path)
        end)
      end)
      if ok then
        watchers[#watchers + 1] = poll
      else
        pcall(function() poll:close() end)
      end
    end
  end

  -------------------------------------------------------------------------
  -- Teardown
  -------------------------------------------------------------------------

  --- Idempotent: stop + close every watcher so no libuv handle leaks (a
  --- leaked fs_poll/fs_event keeps headless Neovim from exiting). Sets
  --- `disposed` first so any already-scheduled-but-not-yet-run callback
  --- no-ops instead of touching a torn-down handle.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true

    for _, w in ipairs(watchers) do
      pcall(function()
        w:stop()
        w:close()
      end)
    end
    watchers = {}
  end

  return handle
end

return M
