--- ExpectedContent — in-memory model of a file's current content.
--- Used as the foundation for external-change detection (docs/design.md §4.5).
---
--- Faithful port of the monorepo's expected-content.ts. The "streaming"
--- aspect is per-file hash tracking; we recompute sha256 from the full
--- content on each access (memoized, invalidated on change). Full recompute
--- is fine for typical assignment file sizes (kilobytes).
---
--- PURE: no Neovim editor API; only provenance.core.sha256.
local sha256 = require("provenance.core.sha256")

local M = {}

--- Convert a {line, character} position to a 0-based offset into content.
--- EXACT port of the TS `_positionToOffset`: clamps `character` to the
--- REMAINING content from the line start (not to that line's length).
--- @param content string
--- @param pos table {line=, character=}
--- @return integer  0-based offset
local function position_to_offset(content, pos)
  local line = 0
  local i = 0 -- 0-based index into content

  while i < #content and line < pos.line do
    if content:sub(i + 1, i + 1) == "\n" then
      line = line + 1
    end
    i = i + 1
  end

  local remaining = #content - i
  local char_offset = math.min(pos.character, remaining)
  return i + char_offset
end

--- Construct from the initial known content of a file (typically read at
--- doc.open).
--- @param initial_content string
--- @return table ec
function M.new(initial_content)
  local self = {}

  local _content = initial_content
  local _hash = nil -- nil = needs recompute

  --- Current full content.
  function self.get_content()
    return _content
  end

  --- Line count. Empty string -> 0. Non-empty with no \n -> 1. Trailing \n
  --- counts an empty line.
  function self.line_count()
    if _content == "" then
      return 0
    end
    local count = 1
    for i = 1, #_content do
      if _content:sub(i, i) == "\n" then
        count = count + 1
      end
    end
    return count
  end

  --- Current hex sha256 of the full content. Memoized; invalidated by
  --- apply_delta/reset.
  function self.hash()
    if _hash == nil then
      _hash = sha256.hex(_content)
    end
    return _hash
  end

  --- Apply a single doc.change delta. Updates content + invalidates cached
  --- hash. delta = { range = { start = {line=,character=}, ["end"] =
  --- {line=,character=} }, text = }.
  function self.apply_delta(delta)
    local start_offset = position_to_offset(_content, delta.range.start)
    local end_offset = position_to_offset(_content, delta.range["end"])
    -- 0-based offset O maps to Lua content:sub(1, O) for the prefix [0,O)
    -- and content:sub(O+1) for the suffix [O,end).
    _content = _content:sub(1, start_offset) .. delta.text .. _content:sub(end_offset + 1)
    _hash = nil
  end

  --- Apply many deltas in order.
  function self.apply_deltas(deltas)
    for _, delta in ipairs(deltas) do
      self.apply_delta(delta)
    end
  end

  --- Replace content entirely (e.g., after fs.external_change reconciliation).
  function self.reset(content)
    _content = content
    _hash = nil
  end

  return self
end

return M
