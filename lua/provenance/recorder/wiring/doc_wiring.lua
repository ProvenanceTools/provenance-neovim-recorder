--- Doc wiring: the Neovim seam between buffer/autocmd signals and the pure
--- doc_events transforms, emitted through the SessionHost's `emit`. Ports the
--- CORE of the monorepo's doc-wiring.ts (recordability filter, open/change/
--- save/close, catch-up for already-open buffers). Paste detection (Plan 6)
--- and external-change detection (Plan 5) are DEFERRED — doc.change always
--- carries source="typed" (hardcoded in doc_events.transform_doc_change), and
--- there is no expected-content model here yet.
local doc_events = require("provenance.recorder.events.doc_events")
local default_sha256 = require("provenance.core.sha256")

local M = {}

local AUGROUP_NAME = "ProvenanceDocWiring"

-- The activation manifest at the workspace root — never recorded, mirrors
-- activation.lua's MANIFEST_NAMES (not exported there, so duplicated here;
-- both must change together if the manifest filename ever changes).
local MANIFEST_RELS = { [".provenance-manifest"] = true, ["provenance-manifest"] = true }

--- content_bytes(buf) -> string
---
--- The single content model used for doc.open's inlined content/hash and
--- doc.save's hash: buffer lines joined by "\n", PLUS one trailing "\n".
---
--- This matches two things that must agree for the analyzer to accept a
--- bundle: (a) Neovim's default `'fixeol'` (on) always terminates a written
--- file with a trailing "\n" regardless of the buffer's own line array, so
--- this is what actually lands on disk (and what seal.lua's raw-byte hash
--- for submission_files sees); and (b) VS Code's `TextDocument.getText()` —
--- what the reference recorder (doc-wiring.ts) and the analyzer's delta-
--- replay reconstruction both assume — models a file ending in "\n" as N+1
--- lines with an empty last line, which is exactly `join(lines, "\n") ..
--- "\n"`.
---
--- Deferred (not handled here — default unix+fixeol is the scope this gate
--- needs): fileformat=dos/mac, `'nobinary'`/`'noeol'` buffers, and the
--- empty-buffer/0-byte-file edge case.
local function content_bytes(buf)
  local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  return table.concat(lines, "\n") .. "\n"
end

--- attach(opts) -> handle
---
--- opts:
---   workspace: string             -- absolute path to the activated workspace root
---   provenance_dir: string|nil    -- absolute path to <workspace>/.provenance/;
---                                    files under it are NEVER recorded (self-loop
---                                    prevention). May be nil in tests.
---   files_under_review: table|nil -- workspace-relative paths; kept for signature
---                                    parity with later plans, unused here.
---   emit: function(kind, data)    -- SessionHost.emit
---   get_hash: function(text) -> hex string; defaults to sha256.hex, injectable
---                                    for tests.
---
--- Returns a handle with handle.dispose().
--- Best-effort realpath: returns the normalized realpath if it resolves,
--- nil otherwise (e.g. the path doesn't exist yet). Kept separate from
--- resolve_dir so callers that need to know resolution failed (to retry
--- later) can tell the difference from "resolved to itself".
local function try_realpath(normalized_path)
  local real = vim.uv.fs_realpath(normalized_path)
  return real and vim.fs.normalize(real) or nil
end

--- Resolve a directory to the same absolute form Neovim uses internally for
--- buffer names (nvim_buf_get_name performs realpath-style resolution of
--- existing path components — e.g. macOS's /tmp and /var are symlinks into
--- /private, so a workspace path built from vim.fn.tempname()/getcwd() can
--- disagree with a buffer's reported name unless both are resolved the same
--- way). Falls back to plain vim.fs.normalize if the path doesn't exist yet
--- or realpath fails, so this stays safe to call before the directory exists.
local function resolve_dir(path)
  if not path then
    return nil
  end
  local normalized = vim.fs.normalize(path)
  return try_realpath(normalized) or normalized
end

function M.attach(opts)
  opts = opts or {}

  -- The workspace is the activated assignment root, so it always exists at
  -- attach() time — its realpath resolution is immediate and stable.
  local workspace = resolve_dir(opts.workspace)

  -- provenance_dir may NOT exist yet at attach() time (e.g. before the
  -- first checkpoint/seal creates it). Resolving it once with a
  -- non-realpath'd fallback would leave `provenance_dir` permanently in a
  -- form (e.g. /var/...) that Neovim's realpath'd buffer names (e.g.
  -- /private/var/... on macOS) never match, letting files created under it
  -- after attach slip through the exclusion (the self-feeding-loop bug).
  -- Instead: cache the realpath once it resolves, but keep retrying inside
  -- is_recordable (autocmd-driven only — never the on_lines hot path)
  -- until it does, so the exclusion becomes effective the moment the
  -- directory exists — never falling back to an un-realpath'd guess.
  local provenance_dir_input = opts.provenance_dir and vim.fs.normalize(opts.provenance_dir) or nil
  local provenance_dir = provenance_dir_input and try_realpath(provenance_dir_input)

  local emit = opts.emit
  local get_hash = opts.get_hash or default_sha256.hex

  local disposed = false

  -- Defensive de-dup for doc.open (mirrors doc-wiring.ts's seenDocs). Keyed
  -- by rel path, never cleared — a closed-then-reopened doc does not refire
  -- doc.open, matching the reference implementation (CLAUDE.md: no registry
  -- deletion on close).
  local seen = {}

  -- De-dup for doc.close: BufDelete and BufUnload both fire for a single
  -- real close, and this module registers one callback on both. Keyed by
  -- buffer id; cleared when the buffer is (re)recognized as open via
  -- BufReadPost/BufNewFile so a genuine close->reopen->close still emits a
  -- second doc.close.
  local closed = {}

  -- Buffers we've called nvim_buf_attach on, and the workspace-relative path
  -- cached at attach time so the on_lines hot path never recomputes
  -- recordability per keystroke.
  local attached_bufs = {}
  local buf_rel = {}

  -------------------------------------------------------------------------
  -- Recordability filter (single source of truth).
  --
  -- Recordable iff: buftype == "" (a normal file buffer — excludes
  -- terminal/help/nofile/quickfix/prompt), the buffer has a name whose
  -- absolute path is inside `workspace`, and it isn't a provenance artifact
  -- (the activation manifest, or anything under `provenance_dir`).
  --
  -- Returns the workspace-relative path on success, nil otherwise, so
  -- callers can reuse it without recomputing.
  -------------------------------------------------------------------------
  local function is_recordable(buf)
    if not vim.api.nvim_buf_is_valid(buf) then
      return nil
    end
    if vim.api.nvim_get_option_value("buftype", { buf = buf }) ~= "" then
      return nil
    end

    local name = vim.api.nvim_buf_get_name(buf)
    if name == "" then
      return nil
    end

    -- Resolve the buffer path the same way (realpath, with normalize
    -- fallback) as workspace/provenance_dir, so the prefix comparison below
    -- is symmetric regardless of which side a symlink sits on.
    local abs = resolve_dir(name)
    if abs ~= workspace and not vim.startswith(abs, workspace .. "/") then
      return nil
    end
    local rel = (abs == workspace) and "" or abs:sub(#workspace + 2)

    if MANIFEST_RELS[rel] then
      return nil
    end
    if provenance_dir_input and not provenance_dir then
      -- Directory didn't exist as of the last attempt; retry now (cheap —
      -- this only runs on autocmd events, never per-keystroke).
      provenance_dir = try_realpath(provenance_dir_input)
    end
    if provenance_dir and (abs == provenance_dir or vim.startswith(abs, provenance_dir .. "/")) then
      return nil
    end

    return rel
  end

  -------------------------------------------------------------------------
  -- doc.open
  -------------------------------------------------------------------------

  --- Emit doc.open for `buf`, reading its text exactly once. No-op if not
  --- recordable or already emitted for this rel path.
  local function emit_doc_open(buf)
    local rel = is_recordable(buf)
    if not rel then
      return
    end
    if seen[rel] then
      return
    end
    seen[rel] = true

    local line_count = #vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    local text = content_bytes(buf)
    local hash = get_hash(text)

    local ev = doc_events.transform_doc_open(rel, hash, text, line_count)
    emit(ev.kind, ev.data)
  end

  -------------------------------------------------------------------------
  -- on_lines (hot path) + attach
  -------------------------------------------------------------------------

  --- Attach nvim_buf_attach to `buf` (idempotent) and cache its rel path.
  local function attach_buffer(buf)
    if attached_bufs[buf] then
      return
    end
    local rel = is_recordable(buf)
    if not rel then
      return
    end

    attached_bufs[buf] = true
    buf_rel[buf] = rel

    vim.api.nvim_buf_attach(buf, false, {
      -- MINIMAL hot-path work: no signing, no canonicalization, no
      -- recordability recompute (rel is looked up from the cache filled at
      -- attach time). emit() only builds the event shape; SessionHost does
      -- the actual chaining/hashing/writing elsewhere.
      on_lines = function(_, b, _changedtick, first, last, new_last, ...)
        if disposed then
          return true -- detach
        end

        local r = buf_rel[b]
        if not r then
          return
        end

        -- Single line-granular delta representing lines [first, last)
        -- replaced by lines [first, new_last). Byte-accurate under the
        -- trailing-newline content model (content_bytes): each buffer line
        -- in that model is "\n"-terminated, including the (possibly empty)
        -- line at the old/new line count, so appending "\n" to the new
        -- lines' join reproduces exactly the bytes being spliced in at
        -- offsetAt(first,0)..offsetAt(last,0). A pure deletion (new_last ==
        -- first) has no replacement text, so text is "".
        local new_lines = vim.api.nvim_buf_get_lines(b, first, new_last, false)
        local text = (new_last > first) and (table.concat(new_lines, "\n") .. "\n") or ""
        local delta = {
          range = {
            start = { line = first, character = 0 },
            ["end"] = { line = last, character = 0 },
          },
          text = text,
        }

        local ev = doc_events.transform_doc_change(r, { delta })
        emit(ev.kind, ev.data)
      end,
      on_detach = function(_, b)
        attached_bufs[b] = nil
        buf_rel[b] = nil
      end,
    })
  end

  -------------------------------------------------------------------------
  -- Autocmds
  -------------------------------------------------------------------------

  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME, { clear = true })

  vim.api.nvim_create_autocmd({ "BufReadPost", "BufNewFile" }, {
    group = augroup,
    desc = "Provenance: doc.open + attach on buffer read/create",
    callback = function(args)
      local buf = args.buf
      if not is_recordable(buf) then
        return
      end
      -- A genuine reopen: allow a later close of this buffer to emit
      -- doc.close again.
      closed[buf] = nil
      emit_doc_open(buf)
      attach_buffer(buf)
    end,
  })

  vim.api.nvim_create_autocmd("BufWritePost", {
    group = augroup,
    desc = "Provenance: doc.save on write",
    callback = function(args)
      local buf = args.buf
      local rel = is_recordable(buf)
      if not rel then
        return
      end

      local text = content_bytes(buf)
      local hash = get_hash(text)

      local ev = doc_events.transform_doc_save(rel, hash)
      emit(ev.kind, ev.data)
    end,
  })

  vim.api.nvim_create_autocmd({ "BufDelete", "BufUnload" }, {
    group = augroup,
    desc = "Provenance: doc.close on delete/unload",
    callback = function(args)
      local buf = args.buf
      -- BufDelete and BufUnload both fire for one real close (e.g. a
      -- single :bwipeout!/:bdelete!); this callback is registered on both,
      -- so de-dup per buffer to emit doc.close exactly once.
      if closed[buf] then
        return
      end

      -- The buffer may already be mid-unload by the time this fires (order
      -- relative to nvim_buf_attach's internal on_detach isn't guaranteed),
      -- so fall back to the rel cached at attach time.
      local rel = is_recordable(buf) or buf_rel[buf]
      if not rel then
        return
      end
      closed[buf] = true

      -- CLAUDE.md/doc-wiring.ts parity: do NOT delete the `seen` de-dup
      -- entry on close — close+reopen is common and should not re-emit
      -- doc.open. Only the buffer attachment is torn down.
      local ev = doc_events.transform_doc_close(rel)
      emit(ev.kind, ev.data)
    end,
  })

  -------------------------------------------------------------------------
  -- Catch-up (PRD §4.2.1): synthetic doc.open for buffers already open when
  -- attach() runs. The `seen` de-dup guards against a race with a live
  -- BufReadPost firing for the same buffer around this same moment.
  -------------------------------------------------------------------------
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_loaded(buf) and is_recordable(buf) then
      emit_doc_open(buf)
      attach_buffer(buf)
    end
  end

  -------------------------------------------------------------------------
  -- Teardown
  -------------------------------------------------------------------------

  local handle = {}

  --- Idempotent: safe to call more than once. After this returns, no
  --- autocmds remain in this augroup, tracked buffers are (best-effort)
  --- detached, and any in-flight on_lines callback detaches itself on its
  --- next invocation via the `disposed` flag.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true

    pcall(vim.api.nvim_del_augroup_by_name, AUGROUP_NAME)

    for buf in pairs(attached_bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.api.nvim_buf_detach, buf)
      end
    end
    attached_bufs = {}
    buf_rel = {}
    closed = {}
  end

  return handle
end

return M
