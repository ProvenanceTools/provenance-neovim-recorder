--- precise_delta.lua — build a VS-Code-shaped doc.change delta from an
--- `on_bytes` edit descriptor.
---
--- WHY THIS EXISTS: Neovim's `on_bytes` reports each edit as a byte-granular
--- splice (start position + old-region span + new-region span). The Provenance
--- format's DocChangeDelta mirrors VS Code's `contentChange`: a precise
--- character-level `range` (in PRE-edit coords) plus exactly the inserted
--- `text`. The analyzer reconstructs by splicing `[offsetAt(start),
--- offsetAt(end)) -> text`, and — critically — its `offsetAt`/`clampPos`
--- index into a JS string, so `character` MUST be counted in UTF-16 code
--- units (packages/analysis-core/src/validation/verify-doc-save-hashes.ts,
--- index/reconstruct-file.ts). Emitting exactly-inserted text (not the whole
--- changed line) is also what keeps the analyzer's `charsTyped` /
--- `charsPasted` stats honest — those sum `delta.text.length`
--- (packages/analysis-core/src/index/stats.ts).
---
--- COORDINATE MODEL (matches on_bytes args):
---   start_row/start_col : edit start, BYTE column, valid in both pre- and
---                         post-edit content (bytes before it are untouched).
---   old_end_row/col     : span of replaced text, as a DELTA from start
---                         (on_bytes gives old_end relative to start). The
---                         absolute pre-edit end line is start_row+old_end_row;
---                         its byte column is start_col+old_end_col when the
---                         span is single-line (old_end_row == 0), else
---                         old_end_col outright.
---   new_end_row/col     : span of inserted text (only needed by the caller to
---                         read `inserted_text` from the live buffer).
---
--- The START character is derivable from the live buffer (its prefix is
--- unchanged), but the END character of a deletion/replacement needs the
--- PRE-edit line, so the caller passes `pre_lines` (a snapshot of the pre-edit
--- lines covering at least rows start_row .. start_row+old_end_row). Pure
--- insertions (old_end == start) never consult a removed line.
local M = {}

--- UTF-16 code-unit column for `byte_col` bytes into `line`. Clamped to the
--- line's UTF-16 length so a byte column at (or past) end-of-line is safe.
--- @param line string  a single line's bytes (no trailing EOL)
--- @param byte_col integer  0-based byte offset into `line`
--- @return integer  0-based UTF-16 column
local function utf16_col(line, byte_col)
  line = line or ""
  if byte_col <= 0 then
    return 0
  end
  if byte_col >= #line then
    -- Whole-line length in UTF-16 units.
    return vim.str_utfindex(line, "utf-16", #line)
  end
  return vim.str_utfindex(line, "utf-16", byte_col)
end

--- Build the delta.
--- @param pre_lines table  pre-edit line strings, 0-based row r -> pre_lines[r+1]
--- @param args table {start_row, start_col, old_end_row, old_end_col,
---                    new_end_row, new_end_col}  (old_end/new_end are DELTAS)
--- @param inserted_text string  exactly the inserted bytes (EOL-joined by caller)
--- @return table delta { range = { start = {line,character},
---                       ["end"] = {line,character} }, text = inserted_text }
function M.build(pre_lines, args, inserted_text)
  local start_line = args.start_row
  local start_char = utf16_col(pre_lines[start_line + 1], args.start_col)

  local end_line = args.start_row + args.old_end_row
  local end_byte_col
  if args.old_end_row == 0 then
    end_byte_col = args.start_col + args.old_end_col
  else
    end_byte_col = args.old_end_col
  end
  local end_char = utf16_col(pre_lines[end_line + 1], end_byte_col)

  return {
    range = {
      start = { line = start_line, character = start_char },
      ["end"] = { line = end_line, character = end_char },
    },
    text = inserted_text,
  }
end

return M
