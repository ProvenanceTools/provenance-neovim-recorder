--- selection_wiring.lua — the Neovim seam between cursor/visual movement and
--- the `selection.change` event, mirroring VS Code's
--- onDidChangeTextEditorSelection (which lives in the monorepo's
--- doc-wiring.ts). VS Code emits a selection.change on EVERY selection/cursor
--- change; this mirrors that cadence via CursorMoved (normal/visual) and
--- CursorMovedI (insert). A cursor-only move is an empty range with
--- was_selection=false; an active visual selection carries the span with
--- was_selection=true (the analogue of VS Code's `!selection.isEmpty`).
---
--- Recordability is delegated to the doc_wiring handle (same recordable-buffer
--- filter + cache doc.change uses), so this never re-derives the workspace /
--- provenance-dir / manifest exclusion logic — mirroring how paste_assembly
--- depends on the doc_wiring handle.
---
--- `character` columns are UTF-16 code units (the format/analyzer contract,
--- see events/precise_delta.lua). Visual-selection ranges are best-effort:
--- the end is made exclusive by one UTF-16 unit past the char under the
--- cursor, which is exact for BMP characters (the common case) and one unit
--- short for an astral char under the cursor — acceptable for a behavioral
--- signal whose integrity-relevant bit is `was_selection`.
local selection_payloads = require("provenance.recorder.events.selection_payloads")

local M = {}

local AUGROUP_NAME = "ProvenanceSelection"
-- See doc_wiring.lua's identical comment: concurrent sessions each call
-- start() once, so the augroup name must be unique per instance.
local instance_seq = 0

--- UTF-16 column for `byte_col` bytes into `line` (clamped to line length).
local function utf16_col(line, byte_col)
  line = line or ""
  if byte_col <= 0 then
    return 0
  end
  if byte_col >= #line then
    return vim.str_utfindex(line, "utf-16", #line)
  end
  return vim.str_utfindex(line, "utf-16", byte_col)
end

--- Is `mode` (from nvim_get_mode().mode / vim.fn.mode()) a visual mode?
--- Covers charwise ("v"), linewise ("V"), and blockwise (CTRL-V, "\22").
local function is_visual_mode(mode)
  local c = mode:sub(1, 1)
  return c == "v" or c == "V" or c == "\22"
end

--- Pure-ish range computation (uses vim.str_utfindex; runs in the nvim
--- harness). Exposed for direct unit testing.
--- @param mode string  the current mode string
--- @param anchor table {row=0-based, col=0-based byte}  (getpos("v"))
--- @param cursor table {row=0-based, col=0-based byte}  (getpos("."))
--- @param get_line function(row0) -> string  the line's bytes (no EOL)
--- @return table { range = { start, ["end"] }, was_selection = boolean }
function M.compute(mode, anchor, cursor, get_line)
  if not is_visual_mode(mode) then
    local ch = utf16_col(get_line(cursor.row), cursor.col)
    return {
      range = {
        start = { line = cursor.row, character = ch },
        ["end"] = { line = cursor.row, character = ch },
      },
      was_selection = false,
    }
  end

  -- Order the two endpoints so start <= end (selection may be backward).
  local lo, hi = anchor, cursor
  if cursor.row < anchor.row or (cursor.row == anchor.row and cursor.col < anchor.col) then
    lo, hi = cursor, anchor
  end

  return {
    range = {
      start = { line = lo.row, character = utf16_col(get_line(lo.row), lo.col) },
      -- End made exclusive: one UTF-16 unit past the char under the cursor.
      ["end"] = { line = hi.row, character = utf16_col(get_line(hi.row), hi.col) + 1 },
    },
    was_selection = true,
  }
end

--- start(opts) -> handle
---
--- opts:
---   emit: function(kind, data)             -- SessionHost.emit
---   doc_wiring_handle: table               -- must expose recordable_rel(buf)
---
--- Returns a handle with handle.dispose(). Idempotent.
function M.start(opts)
  opts = opts or {}
  local emit = opts.emit
  local doc_handle = opts.doc_wiring_handle

  local disposed = false
  instance_seq = instance_seq + 1
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME .. ":" .. instance_seq, { clear = true })

  vim.api.nvim_create_autocmd({ "CursorMoved", "CursorMovedI" }, {
    group = augroup,
    desc = "Provenance: selection.change on cursor/visual movement (recordable buffers only)",
    callback = function(args)
      if disposed then
        return
      end
      -- Never let a detection/emit failure interrupt editing.
      pcall(function()
        local buf = args.buf
        local rel = doc_handle.recordable_rel(buf)
        if not rel then
          return
        end

        local mode = vim.api.nvim_get_mode().mode
        local a = vim.fn.getpos("v")
        local c = vim.fn.getpos(".")
        local anchor = { row = a[2] - 1, col = a[3] - 1 }
        local cursor = { row = c[2] - 1, col = c[3] - 1 }
        local get_line = function(row)
          return vim.api.nvim_buf_get_lines(buf, row, row + 1, false)[1] or ""
        end

        local res = M.compute(mode, anchor, cursor, get_line)
        local ev = selection_payloads.build_selection_change(rel, res.range, res.was_selection)
        emit(ev.kind, ev.data)
      end)
    end,
  })

  local handle = {}

  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    pcall(vim.api.nvim_del_augroup_by_id, augroup)
  end

  handle._augroup_id = augroup
  return handle
end

return M
