--- save_time_checker — Path 1 of 3 external-change emission paths
--- (docs/design.md §4.5, recorder PRD §4.5): the save-time hash check.
---
--- On BufWritePost, doc-wiring calls `check_after_save(rel, abs_path)`
--- BEFORE emitting the normal `doc.save` event (see ORDERING NOTE below).
--- This module reads the file's actual on-disk bytes, compares them against
--- the ExpectedContent model for that path, and — if they diverge, meaning
--- something other than this editor wrote the file between the last known
--- state and this save — emits exactly one `fs.external_change`, then
--- resets the model to disk reality so subsequent tracked edits chain from
--- the truth.
---
--- Composes (does not reimplement):
---   - recorder.state.expected_content_registry — registry.get(rel)
---   - recorder.events.external_change_detector — compare_saved_content
---     (pure; does NOT mutate the ExpectedContent — see its own docstring)
---   - recorder.events.external_change_content — build_external_change_content
---   - recorder.events.explanation_tags — tagger.consume()
---
--- ORDERING NOTE (for the caller, e.g. doc_wiring's BufWritePost handler):
--- `check_after_save` must run BEFORE the normal `doc.save` emit, so that if
--- this save turns out to be over an externally-changed file, the
--- fs.external_change event is recorded ahead of (and thus explains) the
--- doc.save that follows it. Plan 8's coordinator wires this ordering; this
--- module only provides the checker.
---
--- PURE-ish: no Neovim editor API beyond `vim.uv` file I/O (the allowed
--- runtime primitive for `recorder/` per CLAUDE.md's architecture rules).
local external_change_detector = require("provenance.recorder.events.external_change_detector")
local external_change_content = require("provenance.recorder.events.external_change_content")

local M = {}

--- Read a whole file's raw bytes via vim.uv. Never throws. Binary-safe (not
--- vim.fn.readfile, which splits on "\n" and mangles CRLF/CR line endings —
--- see doc_wiring_spec.lua's read_raw for the same idiom). Mirrors
--- commands/seal.lua's read_file_bytes.
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

--- new(opts) -> checker
--- @param opts table {
---   registry: table  -- ExpectedContentRegistry (registry.get(rel))
---   emit: function(kind, data)  -- SessionHost.emit
---   tagger: table  -- ExplanationTagger (tagger.consume())
--- }
--- @return table checker { check_after_save(rel, abs_path) }
function M.new(opts)
  opts = opts or {}

  local registry = opts.registry
  local emit = opts.emit
  local tagger = opts.tagger

  local checker = {}

  --- check_after_save(rel, abs_path)
  ---
  --- rel: workspace-relative path (matches the ExpectedContentRegistry key
  --- and the event payload's `path`). abs_path: absolute path on disk to
  --- read the just-saved bytes from.
  ---
  --- No-ops (never emits, never throws) when: the path was never opened /
  --- isn't tracked (`registry.get(rel) == nil`); the on-disk read fails
  --- (transient — vanished/unreadable file, not a characterizable external
  --- change); or the save was clean (on-disk bytes match what the editor
  --- expected — the normal doc.save path handles that case).
  function checker.check_after_save(rel, abs_path)
    local ec = registry.get(rel)
    if ec == nil then
      return
    end

    local on_disk_content = read_file_bytes(abs_path)
    if on_disk_content == nil then
      return
    end

    local result = external_change_detector.compare_saved_content(ec, on_disk_content)
    if result.kind == "clean_save" then
      -- Matches what the editor expected; do NOT reset — content already
      -- matches, and the normal doc.save path handles this case.
      return
    end

    -- result.kind == "external_change"
    local data = {
      path = rel,
      old_hash = result.old_hash,
      new_hash = result.new_hash,
      diff_size = result.diff_size,
      operation = "modify", -- Path 1 (save-time): the file exists before and after
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
