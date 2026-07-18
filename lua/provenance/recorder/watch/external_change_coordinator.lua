--- external_change_coordinator — Plan 5's final wiring task: ties the three
--- external-change emission paths (docs/design.md §4.5, recorder PRD §4.5)
--- into one unit with a single shared registry, a single shared
--- editor-save-tolerance map, and one dispose. Guarantees EXACTLY ONE
--- `fs.external_change` per genuine external write — no double-emit across
--- paths.
---
--- The three paths (each already implemented; this module only composes
--- them, per CLAUDE.md's "compose, don't reimplement"):
---   - Path 1 (`save_time_checker`): the editor's own `BufWritePost` —
---     compares on-disk bytes to the expected model right after a save.
---   - Path 2 (`fs_watcher`): a `vim.uv.new_fs_poll()` watcher per file in
---     `files_under_review` — catches writes that happen while unfocused, or
---     to a file that isn't even open.
---   - Path 3 (`reload_checker`): Neovim's LAZY `FileChangedShellPost`
---     (focus-gain / explicit `:checktime`) reload-from-disk.
---
--- EXACTLY-ONE-EVENT: two mechanisms combine to guarantee this, and BOTH
--- matter (neither alone is sufficient across every timing window):
---   1. `recent_saves` tolerance (Path 2 only): doc-wiring calls
---      `handle.note_save(rel)` on `BufWritePost` BEFORE
---      `handle.check_after_save(rel, abs_path)`. Path 2's fs_watcher then
---      skips any change to `rel` observed within `tolerance_ms` of that
---      timestamp — so the editor's own save can never masquerade as an
---      external change via Path 2, even if the fs_poll callback happens to
---      fire in that window.
---   2. `ec.reset` after emit: whichever path emits an `fs.external_change`
---      resets the shared ExpectedContent to the on-disk bytes it just
---      observed. Any OTHER path that subsequently observes that same disk
---      state sees `clean_save` (the disk now matches "expected") and emits
---      nothing. This is what protects Path 2 outside the tolerance window,
---      and what protects Path 3 (which has no tolerance window at all —
---      see reload_checker.lua's docstring) against re-reporting a change
---      Path 1 or Path 2 already reported.
--- Together: within the tolerance window, mechanism 1 suppresses Path 2
--- outright; past the window (or for Path 3, which has none), mechanism 2
--- means whichever path observes the change first "claims" it and resets
--- the model, so every other path sees a clean, already-reconciled state.
---
--- Composes (does not reimplement):
---   - recorder.state.expected_content_registry — the ONE shared registry
---   - recorder.watch.save_time_checker — Path 1
---   - recorder.watch.fs_watcher — Path 2
---   - recorder.watch.reload_checker — Path 3
---   - recorder.events.explanation_tags — shared tagger (wired but usually
---     empty until Plan 6/7's formatter/git signals land)
---
--- PURE-ish: no Neovim editor API beyond autocmds/augroups (the allowed
--- runtime primitive for `recorder/` per CLAUDE.md's architecture rules) and
--- what the composed modules already use.
local expected_content_registry = require("provenance.recorder.state.expected_content_registry")
local save_time_checker = require("provenance.recorder.watch.save_time_checker")
local fs_watcher = require("provenance.recorder.watch.fs_watcher")
local reload_checker = require("provenance.recorder.watch.reload_checker")
local explanation_tags = require("provenance.recorder.events.explanation_tags")

local M = {}

local AUGROUP_NAME = "ProvenanceExternalChange"
local DEFAULT_TOLERANCE_MS = 250

local function default_get_now()
  local uv = vim.uv or vim.loop
  return uv.hrtime() / 1e6
end

--- start(opts) -> handle
--- @param opts table {
---   workspace: string             -- absolute path to the activated workspace root
---   files_under_review: string[]  -- workspace-relative paths to track/watch
---   emit: function(kind, data)    -- SessionHost.emit
---   tagger: table|nil             -- ExplanationTagger; defaults to a real
---                                    explanation_tags.new({get_now=get_now})
---                                    so explanation wiring is live but
---                                    usually empty (Plan 6/7 land the marks)
---   get_now: function()->number (ms)|nil, default vim.uv.hrtime()/1e6
---   tolerance_ms: number|nil, default 250
--- }
--- @return table handle {
---   seed_open(rel, content), apply_change(rel, deltas), note_save(rel),
---   check_after_save(rel, abs_path), on_file_changed_shell(buf),
---   registry, dispose()
--- }
function M.start(opts)
  opts = opts or {}

  local workspace = opts.workspace
  local files_under_review = opts.files_under_review or {}
  local emit = opts.emit
  local get_now = opts.get_now or default_get_now
  local tolerance_ms = opts.tolerance_ms or DEFAULT_TOLERANCE_MS
  local tagger = opts.tagger or explanation_tags.new({ get_now = get_now })

  -- ONE shared registry, ONE shared recent_saves map — the foundation both
  -- double-emit-prevention mechanisms rely on.
  local registry = expected_content_registry.new(files_under_review)
  local recent_saves = {}

  local saver = save_time_checker.new({ registry = registry, emit = emit, tagger = tagger })

  local watcher = fs_watcher.start({
    registry = registry,
    workspace = workspace,
    files_under_review = files_under_review,
    emit = emit,
    tagger = tagger,
    recent_saves = recent_saves,
    get_now = get_now,
    tolerance_ms = tolerance_ms,
  })

  local reloader = reload_checker.new({
    registry = registry,
    workspace = workspace,
    emit = emit,
    tagger = tagger,
  })

  local disposed = false

  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })
  vim.api.nvim_create_autocmd("FileChangedShellPost", {
    group = augroup,
    desc = "Provenance: external-change reload-from-disk (Path 3)",
    callback = function(args)
      if disposed then
        return
      end
      -- Never let a handler error propagate into Neovim's own reload
      -- machinery (this fires mid-FileChangedShellPost).
      pcall(reloader.on_file_changed_shell, args.buf)
    end,
  })

  local handle = {}

  --- The shared registry (test / integration seam).
  handle.registry = registry

  --- TEST-ONLY seam: the underlying Path 2 watcher handle, so tests can
  --- drive `handle_path_event` directly (simulating a real fs_poll firing)
  --- without waiting on real poll timing. Not part of the documented
  --- production interface.
  handle._watcher = watcher

  --- seed_open(rel, content) — establish the baseline ExpectedContent for a
  --- file when it's opened. Harmless (get_or_create is a no-op past the
  --- first call for a given rel) to call for a non-watched path; only
  --- meaningful for files in `files_under_review`. doc-wiring calls this
  --- from doc.open in a later integration.
  function handle.seed_open(rel, content)
    registry.get_or_create(rel, content)
  end

  --- apply_change(rel, deltas) — keep the expected model current with
  --- tracked edits. No-op if `rel` isn't tracked. doc-wiring calls this from
  --- doc.change in a later integration.
  function handle.apply_change(rel, deltas)
    local ec = registry.get(rel)
    if ec ~= nil then
      ec.apply_deltas(deltas)
    end
  end

  --- note_save(rel) — record that the editor itself just saved `rel`. Must
  --- be called BEFORE check_after_save (doc-wiring calls this on
  --- BufWritePost, ahead of check_after_save) so Path 2 can recognize and
  --- suppress the resulting on-disk change as the editor's own save rather
  --- than an external one.
  function handle.note_save(rel)
    recent_saves[rel] = get_now()
  end

  --- check_after_save(rel, abs_path) — Path 1. Delegates to the save-time
  --- checker. No-op after dispose.
  function handle.check_after_save(rel, abs_path)
    if disposed then
      return
    end
    saver.check_after_save(rel, abs_path)
  end

  --- on_file_changed_shell(buf) — Path 3, exposed directly for tests; the
  --- FileChangedShellPost autocmd above already wires this internally in
  --- production. No-op after dispose.
  function handle.on_file_changed_shell(buf)
    if disposed then
      return
    end
    reloader.on_file_changed_shell(buf)
  end

  --- dispose() — IDEMPOTENT. Tears down all three paths + the augroup: no
  --- libuv handle or autocmd leak (headless must exit clean). After this
  --- returns, no path emits again.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true

    watcher.dispose()
    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)
  end

  return handle
end

return M
