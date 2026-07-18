--- reload_checker — Path 3 of 3 external-change emission paths (docs/design.md
--- §4.5, recorder PRD §4.5): the LAZY focus/`:checktime`-triggered
--- reload-from-disk.
---
--- Neovim's awareness of on-disk changes is lazy: `FileChangedShell` /
--- `FileChangedShellPost` only fire on focus-gain or an explicit
--- `:checktime` (not at write time). With `autoread` set, Neovim silently
--- reloads the buffer from disk BEFORE `FileChangedShellPost` fires — so by
--- the time `on_file_changed_shell` runs, the buffer's content already
--- equals the file's on-disk content. This module reads the on-disk bytes
--- directly (mirroring Path 1's approach and the submitted-code check's
--- raw-byte comparison, rather than trusting the buffer), compares them
--- against the ExpectedContent model, and — if they diverge — emits exactly
--- one `fs.external_change`, then resets the model to disk reality so
--- subsequent tracked edits chain from the truth.
---
--- NO TOLERANCE WINDOW (unlike Path 2's fs_watcher): a FileChangedShell
--- reload can never be this editor's own save — Neovim does NOT fire
--- FileChangedShell for the editor's own `:w` (that is Path 1's
--- BufWritePost territory) — so a FileChangedShellPost reload is, by
--- construction, always an EXTERNAL change. There is nothing to suppress.
---
--- `operation` is always "modify": a reload implies the file existed both
--- before (the buffer/ExpectedContent had prior content) and after (Neovim
--- just read it back from disk).
---
--- Composes (does not reimplement):
---   - recorder.state.expected_content_registry — registry.get(rel)
---   - recorder.events.external_change_detector — compare_saved_content
---     (pure; does NOT mutate the ExpectedContent — see its own docstring)
---   - recorder.events.external_change_content — build_external_change_content
---   - recorder.events.explanation_tags — tagger.consume()
---
--- PURE-ish: no Neovim editor API beyond `vim.api.nvim_buf_get_name` (to
--- resolve the buffer's path) and `vim.uv` file I/O — the allowed runtime
--- primitives for `recorder/` per CLAUDE.md's architecture rules.
local external_change_detector = require("provenance.recorder.events.external_change_detector")
local external_change_content = require("provenance.recorder.events.external_change_content")

local M = {}

--- Read a whole file's raw bytes via vim.uv. Never throws. Binary-safe (not
--- vim.fn.readfile, which splits on "\n" and mangles CRLF/CR line endings).
--- Exact idiom mirror of save_time_checker.lua's / fs_watcher.lua's
--- read_file_bytes.
--- @param path string
--- @return string|nil  file bytes, or nil if the file can't be read
local function read_file_bytes(path)
  local uv = vim.uv or vim.loop
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

--- Best-effort realpath: returns the normalized realpath if it resolves,
--- nil otherwise (e.g. the path doesn't exist yet). Exact mirror of
--- doc_wiring.lua's try_realpath, duplicated here (not exported there) so
--- this module resolves paths identically to doc_wiring — required so the
--- `rel` computed here always agrees with the `rel` doc_wiring used to key
--- the ExpectedContentRegistry.
local function try_realpath(normalized_path)
  local real = vim.uv.fs_realpath(normalized_path)
  return real and vim.fs.normalize(real) or nil
end

--- Mirror of doc_wiring.lua's resolve_dir: realpath with a normalize
--- fallback, so a workspace/buffer path built before symlink resolution
--- (e.g. macOS's /tmp -> /private/tmp) still compares equal to Neovim's own
--- realpath'd buffer names.
--- @param path string|nil
--- @return string|nil
local function resolve_dir(path)
  if not path then
    return nil
  end
  local normalized = vim.fs.normalize(path)
  return try_realpath(normalized) or normalized
end

--- new(opts) -> checker
--- @param opts table {
---   registry: table    -- ExpectedContentRegistry (registry.get(rel))
---   workspace: string  -- absolute path to the activated workspace root
---   emit: function(kind, data)  -- SessionHost.emit
---   tagger: table      -- ExplanationTagger (tagger.consume())
--- }
--- @return table checker { on_file_changed_shell(buf) }
function M.new(opts)
  opts = opts or {}

  local registry = opts.registry
  local workspace = resolve_dir(opts.workspace)
  local emit = opts.emit
  local tagger = opts.tagger

  local checker = {}

  --- on_file_changed_shell(buf)
  ---
  --- Intended to be wired to a `FileChangedShellPost` autocmd (Task 8's
  --- coordinator wires it; this module only provides the handler). Fires
  --- AFTER Neovim has already reloaded `buf` from disk (autoread), so by
  --- this point the buffer's content equals the on-disk content — this
  --- reads disk directly rather than the buffer, matching Path 1's
  --- approach.
  ---
  --- No-ops (never emits, never throws) when: the buffer has no name; the
  --- buffer's path resolves outside `workspace`; the path isn't tracked
  --- (`registry.get(rel) == nil`, i.e. never opened / not under review);
  --- the on-disk read fails (transient — not a characterizable external
  --- change); or the reload was clean (on-disk bytes already match what the
  --- editor expected — nothing changed relative to belief).
  --- @param buf integer
  function checker.on_file_changed_shell(buf)
    local name = vim.api.nvim_buf_get_name(buf)
    if name == "" then
      return
    end

    local abs = resolve_dir(name)
    if abs ~= workspace and not vim.startswith(abs, workspace .. "/") then
      return
    end
    local rel = (abs == workspace) and "" or abs:sub(#workspace + 2)

    local ec = registry.get(rel)
    if ec == nil then
      return
    end

    local on_disk_content = read_file_bytes(abs)
    if on_disk_content == nil then
      return
    end

    local result = external_change_detector.compare_saved_content(ec, on_disk_content)
    if result.kind == "clean_save" then
      -- A benign/no-op reload: on-disk content already matches what the
      -- editor expected. Do NOT reset — nothing to reconcile.
      return
    end

    -- result.kind == "external_change". No tolerance-window skip here (see
    -- module docstring): a FileChangedShell reload is never this editor's
    -- own save.
    local data = {
      path = rel,
      old_hash = result.old_hash, -- EXPECTED (what the editor believed, pre-reload)
      new_hash = result.new_hash, -- ACTUAL (on disk, post-reload)
      diff_size = result.diff_size,
      operation = "modify", -- a reload means the file existed before and after
    }

    local content_fields = external_change_content.build_external_change_content(on_disk_content)
    data.new_content_size = content_fields.new_content_size
    if content_fields.new_content ~= nil then
      data.new_content = content_fields.new_content
    else
      data.new_content_head = content_fields.new_content_head
      data.new_content_tail = content_fields.new_content_tail
    end

    local explanation = tagger.consume()
    if explanation ~= nil then
      data.explanation = explanation
    end

    emit("fs.external_change", data)

    -- Reset AFTER emitting: the detector does not mutate; this checker owns
    -- resetting the model to disk reality so subsequent tracked edits chain
    -- from the truth (CLAUDE.md / PRD §4.5).
    ec.reset(on_disk_content)
  end

  return checker
end

return M
