--- Pure doc-event transforms: editor signal -> {kind, data} event shape.
--- No Neovim API, no hashing, no I/O — the caller (recorder wiring) passes
--- precomputed content_hash and a workspace-relative path. These functions
--- feed the chain + writer (later tasks); they never touch it themselves.
local json = require("provenance.core.json")

local DEFAULT_MAX_INLINE_BYTES = 64 * 1024

local M = {}

--- text's byte length (Lua `#` counts UTF-8 bytes) decides inline vs
--- truncated. `max_inline_bytes` defaults to 64KB when nil.
function M.transform_doc_open(path, content_hash, text, line_count, max_inline_bytes)
  max_inline_bytes = max_inline_bytes or DEFAULT_MAX_INLINE_BYTES
  local byte_len = #text

  if byte_len <= max_inline_bytes then
    return {
      kind = "doc.open",
      data = {
        path = path,
        sha256 = content_hash,
        line_count = line_count,
        content = text,
      },
    }
  end

  return {
    kind = "doc.open",
    data = {
      path = path,
      sha256 = content_hash,
      line_count = line_count,
      truncated = true,
    },
  }
end

--- deltas is a list of {range={start={line,character},end={line,character}},
--- text}, passed through as-is. nil/empty -> an empty json array (`[]`), not
--- an object (`{}`).
function M.transform_doc_change(path, deltas)
  return {
    kind = "doc.change",
    data = {
      path = path,
      deltas = json.array(deltas or {}),
      source = "typed",
    },
  }
end

function M.transform_doc_save(path, content_hash)
  return {
    kind = "doc.save",
    data = { path = path, sha256 = content_hash },
  }
end

function M.transform_doc_close(path)
  return {
    kind = "doc.close",
    data = { path = path },
  }
end

return M
