--- fs_watcher — Path 2 of 3 external-change emission paths (docs/design.md
--- §4.5, recorder PRD §4.5): a `vim.uv` filesystem watcher over the resolved
--- scope. Catches external writes/creates/deletes that happen while Neovim
--- is unfocused, or doesn't have the file open at all — the path that fires
--- PROMPTLY, unlike Neovim's lazy focus-based `FileChangedShell` reload
--- (which only fires on focus-gain / an explicit `:checktime`). Path 1
--- (save-time hash check, `save_time_checker.lua`) covers the complementary
--- "editor has the file open and just wrote it" case.
---
--- Faithful port of the monorepo's wiring/fs-watcher.ts. See its top-of-file
--- design-notes comment for the modify/create/delete rules; this module
--- mirrors them:
---   - MODIFY: skip if within `tolerance_ms` of the file's last editor save
---     (`recent_saves[rel]`, populated by Path 1 / the coordinator) — that
---     change is already captured via `doc.save`. Otherwise
---     `compare_saved_content` against the registry entry: `clean_save` ->
---     skip (no real change), `external_change` -> emit + `ec.reset`.
---   - CREATE: only for paths the registry `is_watched` and with no existing
---     registry entry — emit `old_hash=""` + seed the registry so subsequent
---     edits chain from reality.
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
---       this directly for every create/modify/delete/skip case. ITS DECISION
---       LOGIC DOES NOT CHANGE for the path-scope port — every caller,
---       whichever of (B) below reaches it, is re-checked against
---       `resolve_path_role` BEFORE it is ever handed a path (see the design
---       notes below), so (A) itself needs no scope-awareness of its own.
---   (B) A thin `vim.uv` watcher seam wiring OS/poll/event notifications to
---       (A). Exercised by exactly one integration test using `vim.wait`.
---
--- ## Two watcher mechanisms in (B), one per entry SHAPE (path-scope design
--- ## spec §4.2; path-scope-provnvim.md §4.1)
---
--- **Exact entries** (`scope.track` entries where `path_scope.is_exact_entry`
--- is true): UNCHANGED. One `vim.uv.new_fs_poll()` per entry, exactly as
--- before path-scope existed — 1.x and exact-2.0 behaviour stay byte-
--- identical.
---
--- **Rule entries** (a `src/` folder or `*.java` suffix): a folder or suffix
--- has no single file to poll, and the file list under it is not knowable at
--- session start (live membership, path-scope design spec §4.1). Two
--- sub-mechanisms, each doing exactly one job:
---   - `vim.uv.new_fs_event()`, ONE NON-RECURSIVE handle PER DIRECTORY inside
---     a reachable subtree, answers exactly one question: "a name appeared or
---     changed in this directory." It is used ONLY FOR DISCOVERY of new
---     paths — never to classify or emit an event directly. Non-recursive,
---     one-per-directory, deliberately: `UV_FS_EVENT_RECURSIVE` works on
---     macOS and Windows but NOT on Linux (inotify is not recursive), and a
---     shape that behaves identically on all three platforms beats one that
---     is faster on the platform a contributor happens to be testing on.
---   - Once a path is discovered and resolves `reviewed`, it gets an ordinary
---     `vim.uv.new_fs_poll()` handle — EXACTLY the exact-entry mechanism —
---     and ALL subsequent modify/delete detection for it runs through the
---     same `handle.handle_path_event` exact entries already use. This is
---     not incidental: `fs_event` backends miss rename-into-place atomic
---     writes (a common editor save pattern — see the KNOWN NUANCE comment
---     below for the analogous `fs_poll` baseline race, and the historical
---     reason THIS module chose `fs_poll` over `fs_event` for exact entries
---     in the first place). Routing rule-matched files through `fs_event`
---     alone would make `src/Main.java` LESS reliably watched than
---     `Main.java` named exactly in the same manifest.
---
--- ## A folder root that does not exist yet at session start (path-scope
--- ## design spec D3)
---
--- A snapshot that never discovers a directory the student creates later is
--- an R2 false-accusation-by-omission shape: "I wrote it in a new file" is
--- ordinary, innocent behaviour, and a course writing `src/` for a from-
--- scratch assignment is the ordinary case, not the exotic one. When a
--- folder entry's directory (`src/`, or an intermediate segment of a deeper
--- one like `a/b/c/`) is absent at `start()`, this module walks UP to the
--- nearest EXISTING ancestor — bounded by the workspace root, never above
--- it — and opens a non-recursive `fs_event` "pursuit" handle there
--- (`pursue()` below). On every notification it re-checks whether the
--- target now exists and, if not, whether the next path segment toward it
--- does, cascading its own watch one level deeper and recursing
--- synchronously as far as already-created segments allow — this handles a
--- batched `mkdir -p a/b/c` regardless of whether the OS surfaces that as
--- one notification or several, and in whatever order. The moment the
--- target itself exists, it gets exactly the same `visit_dir(..., true)`
--- treatment any other directory that appears mid-session already gets —
--- its files are genuinely NEW, so they are reported as creates, not seeded
--- silently.
---
--- RETENTION, stated explicitly: every pursuit handle opened along the way
--- is kept for the rest of the session, never closed once superseded by a
--- deeper one or by the target's own promotion. A directory on the path can
--- be deleted and recreated (`rm -rf src && git checkout src`, or a build
--- step that wipes and regenerates) — closing a pursuit handle early would
--- permanently lose detection for the rest of the session the next time
--- that happens, which is the exact silent-gap failure this mechanism
--- exists to close. The cost is handle count growing with promotion depth
--- (one extra `fs_event` handle per path segment actually walked), bounded
--- by the target's own path depth, not by workspace size — worth it given
--- the alternative is a session that silently stops noticing.
---
--- ## The editor's watcher is a coarse pre-filter ONLY (non-negotiable —
--- ## path-scope design spec §4.2)
---
--- Neovim's autocmd patterns, `vim.fs` matching, and libuv's own filtering
--- (directory names, `fs_event`'s coalesced/sometimes-garbage `filename`
--- argument — see the empirical note on `visit_dir`'s callback below) are
--- NOT the matcher. `path_scope.resolve_path_role` is the ONLY matcher, and
--- EVERY path either mechanism in (B) discovers is re-checked against it
--- before anything is admitted to the registry, opened as a poll handle, or
--- handed to `handle.handle_path_event`. A port that emitted on its
--- watcher's verdict alone would make the same manifest watch different
--- files on different editors — the exact divergence risk this whole feature
--- exists to prevent.
---
--- ## Bounding the directory-watcher count (path-scope-provnvim.md §4.1)
---
--- Directory `fs_event` handles are opened ONLY for subtrees a rule entry can
--- actually reach:
---   - NO rule entries at all (every `scope.track` entry exact) -> ZERO
---     directory watchers. The watcher layer is bit-identical to today.
---   - A folder entry `src/` -> only under that prefix.
---   - A suffix entry `*.java` -> the WHOLE tree (a suffix matches at any
---     depth), minus hard-excluded subtrees.
--- Hard-excluded directories (`.git/`, `.provenance/`) are pruned using
--- `workspace_walk.has_hard_excluded_segment` (the SAME rule the seal's own
--- walk uses) — a `.provenance/` watcher would be a feedback loop: the
--- session writer appends to the `.slog`, the watcher fires, and the
--- recorder records its own log being written.
---
--- ## The decorative-cap hazard, and how this module avoids it
---
--- `is_watched` returning true does NOT itself admit a path — `get_or_create`
--- does, and the cap tests the registry's map SIZE. So opening a poll handle
--- for a rule-discovered path WITHOUT calling `get_or_create` in the same
--- step would leave the map's size never reflecting what is actually being
--- watched, making the cap decorative: unbounded poll handles could open
--- while `cap_hit()` stayed false forever — worse than no cap at all, because
--- `cap_hit` is what a later seal writes into a SIGNED bundle manifest as
--- `scope_capped`. Every path that gets admitted to a poll handle in this
--- module (`seed_file` and `discover_new` below) calls `registry.is_watched`
--- to gate admission and `registry.get_or_create` to admit, IN THE SAME STEP,
--- before the poll handle is opened.
---
--- Two admission flavours, deliberately different, both keyed off whether the
--- path is genuinely NEW to the session or was already there:
---   - `seed_file` (used only for pre-existing files found by the one-time
---     initial workspace walk at `start()`): admits SILENTLY — no
---     `fs.external_change` emitted. A file that already existed before this
---     session started was not "created" by anything this session observed;
---     synthesizing a create event for it would misrepresent the timeline
---     (the exact `R2` false-accusation shape path-scope-design.md §9 warns
---     about). This mirrors how an exact entry's pre-existing, never-opened
---     file produces no synthetic event either — `fs_poll`'s own async
---     baseline (see the KNOWN NUANCE comment) absorbs its starting state.
---   - `discover_new` (used when `fs_event` reports a name that was not
---     already known inside a watched directory, i.e. genuinely appeared
---     during the session): opens the poll handle THEN calls
---     `handle.handle_path_event` once, synchronously, so the file's
---     admission and its `create` event are the SAME atomic step — exactly
---     how an exact entry's own first-ever create is already handled by (A).
---
--- Composes (does not reimplement): recorder.state.expected_content_registry,
--- recorder.events.external_change_detector (compare_saved_content),
--- recorder.events.external_change_content (build_external_change_content),
--- recorder.events.explanation_tags (tagger.consume()), recorder.io.workspace_walk
--- (has_hard_excluded_segment — the shared hard-exclusion rule), core.path_scope
--- (resolve_path_role/is_exact_entry — the ONLY matcher), core.sha256.
local external_change_detector = require("provenance.recorder.events.external_change_detector")
local external_change_content = require("provenance.recorder.events.external_change_content")
local sha256 = require("provenance.core.sha256")
local path_scope = require("provenance.core.path_scope")
local workspace_walk = require("provenance.recorder.io.workspace_walk")

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
---   scope: table                  -- ResolvedScope {track, ignore, attachments}
---                                    (see core.manifest.scope_from_manifest —
---                                    the ONLY way to build one)
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
  local scope = opts.scope or { track = {}, ignore = {}, attachments = {} }
  local emit = opts.emit
  local tagger = opts.tagger
  local recent_saves = opts.recent_saves or {}
  local get_now = opts.get_now or default_get_now
  local tolerance_ms = opts.tolerance_ms or DEFAULT_TOLERANCE_MS
  local poll_interval_ms = opts.poll_interval_ms or DEFAULT_POLL_INTERVAL_MS

  local disposed = false
  local watchers = {}

  -- Every rel path that already has (or is in the process of getting) an
  -- fs_poll handle — exact entries populate this too, so a rule entry that
  -- happens to ALSO match an already-poll-watched exact entry never gets a
  -- second, duplicate handle.
  local polled = {}

  -- TEST-ONLY counter: how many directory fs_event handles were actually
  -- opened. Exposed via handle._dir_watcher_count() below so tests can
  -- assert the handle-count bounding (path-scope-provnvim.md §4.1) without
  -- reaching into libuv internals — an all-exact scope must open zero.
  local dir_watcher_count = 0

  local handle = {}

  -------------------------------------------------------------------------
  -- (A) Pure-ish decision handler — callable directly by tests. UNCHANGED
  -- decision logic (do not modify): every caller below has already
  -- re-checked resolve_path_role before reaching here.
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
  -- (B) Thin vim.uv watcher seam.
  -------------------------------------------------------------------------

  --- Open one `fs_poll` handle for `rel` (`abs_path`), exactly the
  --- exact-entry mechanism, shared by exact entries and rule-discovered
  --- paths alike. No-op (idempotent) if `rel` already has one.
  --- @param rel string
  --- @param abs_path string
  local function open_poll_handle(rel, abs_path)
    if polled[rel] then
      return
    end
    polled[rel] = true

    local poll = uv.new_fs_poll()
    if not poll then
      return
    end
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

  -- Exact entries: UNCHANGED. One fs_poll per scope.track entry whose form
  -- is exact — filtered from `scope.track`, which the path-scope port lets
  -- also contain folder/suffix rule entries now.
  for _, entry in ipairs(scope.track or {}) do
    if path_scope.is_exact_entry(entry) then
      open_poll_handle(entry, workspace .. "/" .. entry)
    end
  end

  -- -----------------------------------------------------------------------
  -- Rule entries: fs_event for discovery, fs_poll for change detection
  -- (path-scope-provnvim.md §4.1). Only built when at least one rule entry
  -- exists — an all-exact scope opens ZERO directory watchers.
  -- -----------------------------------------------------------------------

  local has_rule_entry = false
  local has_suffix_rule = false
  local folder_roots = {}
  for _, entry in ipairs(scope.track or {}) do
    if not path_scope.is_exact_entry(entry) then
      has_rule_entry = true
      if entry:sub(1, 1) == "*" then
        has_suffix_rule = true
      else
        -- Folder form, e.g. "src/" -> directory rel path "src". A root that
        -- is itself hard-excluded (".provenance/", ".git/", or nested under
        -- either) never becomes a walk root or a pursuit target — same rule
        -- workspace_walk / resolve_path_role apply everywhere else in this
        -- module. (A manifest naming such a root is nonsensical, but this
        -- module does not trust that upstream validation always ran.)
        local root = entry:sub(1, -2)
        if not (
          workspace_walk.has_hard_excluded_segment(root)
          or path_scope.is_hard_excluded(root .. "/")
        ) then
          folder_roots[#folder_roots + 1] = root
        end
      end
    end
  end

  if has_rule_entry then
    -- rel dir path -> { known = { name -> true } }. Also doubles as the
    -- de-dup guard against re-visiting the same directory twice (e.g. two
    -- overlapping folder entries, or a directory reached via recursion
    -- after already being a walk root). `pursue()` below deliberately
    -- clears entries out of this table when it re-promotes a directory
    -- that was deleted and recreated — see its own comment.
    local dirs = {}

    -- rel dir path -> true: every directory that already has (or is in the
    -- process of getting) a pursuit `fs_event` handle from `pursue()`
    -- below — guards against opening a second one for the same directory
    -- when a deeper pursuit re-derives the same ancestor, or when a later
    -- notification re-enters `pursue` for a level already being watched.
    local pursuit_watched = {}

    --- Silently admit a pre-existing file found by the initial workspace
    --- walk: registers it with the registry (subject to the cap) and opens
    --- its fs_poll handle, but emits NOTHING — see this module's own
    --- docstring for why a pre-existing file must never be reported as
    --- "created". No-op if `rel` already has a poll handle (e.g. it is also
    --- an exact entry).
    --- @param rel string
    --- @param abs_path string
    local function seed_file(rel, abs_path)
      if polled[rel] then
        return
      end
      if not registry.is_watched(rel) then
        return
      end
      local content = read_file_bytes(abs_path)
      if content == nil then
        -- Unreadable (permissions, or raced away between scandir and read):
        -- skip silently. The next fs_event/fs_poll cycle, if any, gets
        -- another chance; there is no event to emit for a file whose
        -- content we could never establish a baseline for.
        return
      end
      -- Admission happens in the SAME step as opening the poll handle —
      -- the decorative-cap hazard this module's docstring describes.
      registry.get_or_create(rel, content)
      open_poll_handle(rel, abs_path)
    end

    --- Admit and report a path that genuinely appeared during the session
    --- (discovered via an fs_event directory notification). Opens the poll
    --- handle FIRST, then hands off to handle_path_event once, synchronously
    --- — its own CREATE branch is what actually admits the path to the
    --- registry (the same atomic admission-and-emit exact entries already
    --- get on their own first create). No-op if `rel` already has a handle.
    --- @param rel string
    --- @param abs_path string
    local function discover_new(rel, abs_path)
      if polled[rel] then
        return
      end
      if not registry.is_watched(rel) then
        return
      end
      open_poll_handle(rel, abs_path)
      pcall(handle.handle_path_event, rel, abs_path)
    end

    local visit_dir -- forward decl (recursive)

    --- Open one non-recursive fs_event handle on `dir_abs` (`dir_rel`).
    --- On any notification, re-scans the directory and diffs against the
    --- last-known children to find newly-appeared names — never trusts the
    --- callback's own `filename` literally (empirically observed to be
    --- unreliable: a coalesced "rename" for both creates AND plain
    --- modifies, and occasionally a garbage placeholder value, on this
    --- module's own author's platform). Every discovered directory gets
    --- `visit_dir`'d (live mode: files inside are treated as genuinely new,
    --- not seeded silently); every discovered file is re-checked against
    --- `resolve_path_role` before `discover_new` is ever called.
    --- @param dir_abs string
    --- @param dir_rel string
    local function open_dir_event_handle(dir_abs, dir_rel)
      local d = dirs[dir_rel]
      local ev = uv.new_fs_event()
      if not ev then
        return
      end
      local ok = ev:start(dir_abs, {}, function(_err, _filename, _events)
        if disposed then
          return
        end
        vim.schedule(function()
          if disposed then
            return
          end
          pcall(function()
            local known = d.known
            local scan = uv.fs_scandir(dir_abs)
            if not scan then
              return
            end
            local fresh = {}
            while true do
              local name, ftype = uv.fs_scandir_next(scan)
              if name == nil then
                break
              end
              fresh[name] = true
              if not known[name] then
                local child_rel = dir_rel == "" and name or (dir_rel .. "/" .. name)
                local child_abs = dir_abs .. "/" .. name
                if ftype == "directory" then
                  if not (
                    workspace_walk.has_hard_excluded_segment(name)
                    or path_scope.is_hard_excluded(child_rel .. "/")
                  ) then
                    visit_dir(child_abs, child_rel, true)
                  end
                elseif ftype == "file" then
                  if path_scope.resolve_path_role(child_rel, scope) == "reviewed" then
                    discover_new(child_rel, child_abs)
                  end
                end
                -- links/other entry types: not discovered by this watcher.
              end
            end
            d.known = fresh
          end)
        end)
      end)
      if ok then
        watchers[#watchers + 1] = ev
        dir_watcher_count = dir_watcher_count + 1
      else
        pcall(function() ev:close() end)
      end
    end

    --- Walk `dir_abs` (`dir_rel`), opening a directory fs_event handle for
    --- itself and every non-hard-excluded subdirectory, and admitting every
    --- `reviewed` file found. `is_live` selects which admission flavour
    --- files get: false (the one-time initial walk from `start()`) seeds
    --- silently; true (a directory that appeared DURING the session, found
    --- via `open_dir_event_handle` above) reports each file inside as newly
    --- discovered, since the whole subtree just appeared. Idempotent per
    --- `dir_rel` — guards against re-visiting the same directory twice
    --- (e.g. two overlapping folder entries).
    --- @param dir_abs string
    --- @param dir_rel string
    --- @param is_live boolean
    visit_dir = function(dir_abs, dir_rel, is_live)
      if dirs[dir_rel] ~= nil then
        return
      end
      local known = {}
      dirs[dir_rel] = { known = known }
      -- Open the watcher BEFORE scanning: a name that appears in the tiny
      -- window between scandir and here would otherwise never be reported
      -- by anything (same category of race fs_poll's own async-baseline
      -- KNOWN NUANCE already accepts elsewhere in this module).
      open_dir_event_handle(dir_abs, dir_rel)

      local scan = uv.fs_scandir(dir_abs)
      if not scan then
        -- Directory unreadable, or a genuinely tight race: `dir_abs` was
        -- just confirmed to exist (either by the parent walk's own scandir
        -- entry, or by `pursue()`'s own stat check immediately before
        -- calling here) and vanished again before this scandir ran. A walk
        -- ROOT that simply does not exist YET never reaches this function
        -- at all any more — see `pursue()` below, which is what the caller
        -- routes a missing folder root through instead. The directory
        -- handle just opened above still gets a chance to observe this
        -- directory changing again later (including disappearing and
        -- reappearing, which `pursue`'s own retained ancestor handle also
        -- independently notices — see its docstring).
        return
      end
      while true do
        local name, ftype = uv.fs_scandir_next(scan)
        if name == nil then
          break
        end
        known[name] = true
        local child_rel = dir_rel == "" and name or (dir_rel .. "/" .. name)
        local child_abs = dir_abs .. "/" .. name
        if ftype == "directory" then
          if not (
            workspace_walk.has_hard_excluded_segment(name)
            or path_scope.is_hard_excluded(child_rel .. "/")
          ) then
            visit_dir(child_abs, child_rel, is_live)
          end
        elseif ftype == "file" then
          if path_scope.resolve_path_role(child_rel, scope) == "reviewed" then
            if is_live then
              discover_new(child_rel, child_abs)
            else
              seed_file(child_rel, child_abs)
            end
          end
        end
        -- links/other entry types: not watched here (the seal's own walk —
        -- workspace_walk.lua — is the module responsible for disclosing a
        -- dropped symlink; this watcher's job is discovery, not disclosure).
      end
    end

    --- Nearest EXISTING ancestor directory of `rel` (a folder root's rel
    --- path, no trailing slash), bounded at the workspace root — `""` —
    --- which always exists for a running session and is never itself
    --- walked past. Pure stat-walk-up, no side effects.
    --- @param rel string
    --- @return string  existing ancestor rel path ("" == workspace root)
    local function nearest_existing_dir(rel)
      local cur = rel
      while cur ~= "" do
        local st = uv.fs_stat(workspace .. "/" .. cur)
        if st and st.type == "directory" then
          return cur
        end
        cur = cur:match("^(.*)/[^/]+$") or ""
      end
      return ""
    end

    --- Pursue a folder root that does not exist yet (or existed, then was
    --- deleted) from `cur_rel`/`cur_abs` — an ancestor of `target_rel` known
    --- to currently exist — toward `target_rel`/`target_abs` itself. See
    --- this module's own top-of-file docstring section "A folder root that
    --- does not exist yet at session start" for the full design rationale;
    --- summary here:
    ---
    ---   1. Re-check FIRST, every time this runs (both the initial call and
    ---      every subsequent notification): if `target_abs` already exists,
    ---      promote — hand off to `visit_dir(target_abs, target_rel, true)`,
    ---      the SAME live-discovery treatment any other mid-session-
    ---      appeared directory already gets — and stop pursuing. This closes
    ---      the race between resolving `cur` and getting here, and (via the
    ---      recursive step 3 below) the "mkdir -p a/b/c may fire as one
    ---      notification or several, in any order" race too.
    ---   2. Otherwise, make sure a pursuit `fs_event` handle is watching
    ---      `cur_abs` (no-op if one already is). RETAINED for the rest of
    ---      the session, never closed early — see the docstring section
    ---      above for why (delete + recreate must keep working).
    ---   3. Advance synchronously as far as currently possible: re-derive
    ---      the next path segment beyond `cur_rel` toward `target_rel` and,
    ---      if it already exists on disk, recurse into it immediately
    ---      (rather than waiting for a notification that may never come
    ---      for it specifically, e.g. if it appeared in the same batch as
    ---      segments already accounted for).
    ---
    --- If `target_rel` was visited before (this is a RE-promotion after a
    --- delete + recreate — the reason the ancestor handle in step 2 is
    --- retained rather than closed), `visit_dir`'s own re-visit guard
    --- (`dirs[dir_rel] ~= nil`) would otherwise block a fresh visit of what
    --- is, on disk, a brand-new directory — so the promotion branch clears
    --- the stale `dirs` bookkeeping for `target_rel` and everything nested
    --- under it first. Stale handles from the PRIOR visit (now watching a
    --- deleted path) are left alone, not proactively closed: harmless
    --- (their next scandir/stat simply fails and they no-op), and closing
    --- them is unnecessary work this fix does not need to do; `dispose()`
    --- closes everything regardless at teardown.
    --- @param target_rel string
    --- @param target_abs string
    --- @param cur_rel string
    --- @param cur_abs string
    local function pursue(target_rel, target_abs, cur_rel, cur_abs)
      local target_st = uv.fs_stat(target_abs)
      if target_st and target_st.type == "directory" then
        if dirs[target_rel] ~= nil then
          local prefix = target_rel .. "/"
          for key in pairs(dirs) do
            if key == target_rel or key:sub(1, #prefix) == prefix then
              dirs[key] = nil
            end
          end
        end
        visit_dir(target_abs, target_rel, true)
        return
      end

      if cur_rel == target_rel then
        -- Unreachable in practice (the stat above would have matched), but
        -- guards the remainder/next-segment math below against an empty
        -- remainder.
        return
      end

      if not pursuit_watched[cur_rel] then
        pursuit_watched[cur_rel] = true
        local ev = uv.new_fs_event()
        if ev then
          local ok = ev:start(cur_abs, {}, function(_err, _filename, _events)
            if disposed then
              return
            end
            vim.schedule(function()
              if disposed then
                return
              end
              pcall(pursue, target_rel, target_abs, cur_rel, cur_abs)
            end)
          end)
          if ok then
            watchers[#watchers + 1] = ev
            dir_watcher_count = dir_watcher_count + 1
          else
            pcall(function() ev:close() end)
          end
        end
      end

      local remainder = cur_rel == "" and target_rel or target_rel:sub(#cur_rel + 2)
      local next_seg = remainder:match("^[^/]+")
      if next_seg == nil then
        return
      end
      local next_rel = cur_rel == "" and next_seg or (cur_rel .. "/" .. next_seg)
      local next_abs = workspace .. "/" .. next_rel
      local next_st = uv.fs_stat(next_abs)
      if next_st and next_st.type == "directory" then
        pursue(target_rel, target_abs, next_rel, next_abs)
      end
    end

    if has_suffix_rule then
      -- A suffix rule matches at any depth, so it needs the WHOLE tree; the
      -- workspace root always exists for a running session, so no missing-
      -- root case applies here.
      visit_dir(workspace, "", false)
    else
      for _, root in ipairs(folder_roots) do
        local root_abs = workspace .. "/" .. root
        local root_st = uv.fs_stat(root_abs)
        if root_st and root_st.type == "directory" then
          visit_dir(root_abs, root, false)
        else
          -- The folder does not exist yet at session start — walk up to
          -- the nearest existing ancestor and pursue the target from
          -- there. See `pursue`'s own docstring above.
          local anc_rel = nearest_existing_dir(root)
          local anc_abs = workspace .. (anc_rel == "" and "" or ("/" .. anc_rel))
          pursue(root, root_abs, anc_rel, anc_abs)
        end
      end
    end
  end

  --- TEST-ONLY seam: how many directory fs_event handles this call to
  --- start() opened in total (monotonic — not decremented by dispose()).
  --- Lets tests assert the handle-count bounding directly (path-scope-
  --- provnvim.md §4.1) — an all-exact scope must report zero — without
  --- reaching into libuv internals. Not part of the documented production
  --- interface.
  function handle._dir_watcher_count()
    return dir_watcher_count
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
