--- paste_payload.lua — pure helper that fills the inline-content fields on
--- a `paste` event.
---
--- Faithful port of the monorepo's events/paste-payload.ts (recorder PRD
--- §4.2 paste row + §4.3). Close variant of the fs.external_change content
--- builder (events/external_change_content.lua): same 65536/512 constants
--- and the same UTF-16-code-unit head/tail slicing, plus a `sha256` field
--- over the full pasted text.
---
--- PURE: no Neovim editor API beyond core.sha256 (vim.fn.sha256 under the
--- hood), no chain/canonicalization/signing. Byte length is `#text` (Lua
--- strings are byte arrays, same as `Buffer.byteLength(text, 'utf8')`).
---
--- UTF-16-code-unit slicing (the port subtlety, duplicated from
--- external_change_content.lua rather than shared — see that module's
--- header for the full rationale): the TS source uses JS `text.slice(0,
--- 512)` / `text.slice(-512)`, which count UTF-16 CODE UNITS, not bytes and
--- not codepoints. A BMP codepoint (<= U+FFFF) is 1 UTF-16 unit; an astral
--- codepoint (>= U+10000, e.g. most emoji) is a surrogate pair = 2 UTF-16
--- units. We decode `text` from UTF-8 into codepoints and accumulate
--- UTF-16-unit cost per codepoint to find the same boundary JS would.
---
--- DELIBERATE DEVIATION (same as external_change_content.lua): JS `slice`
--- can legally cut a string BETWEEN the two code units of an astral char's
--- surrogate pair, producing a lone (unpaired) surrogate. Lua/UTF-8 has no
--- representation for a lone surrogate, so this port never splits an
--- astral codepoint: it cuts BEFORE it instead, keeping head/tail at <=
--- 512 UTF-16 units (never more) and always valid UTF-8. `content_head` /
--- `content_tail` are informational preview fields — never hashed or
--- chain-verified — so this is analyzer-irrelevant.
---
--- The head/tail decode/slice helpers below are a deliberate copy of
--- external_change_content.lua's private helpers (module isolation: core/
--- and recorder/events/ modules are pure and self-contained, not sharing
--- private internals), not a shared dependency.
local sha256 = require("provenance.core.sha256")

local M = {}

--- Max UTF-8 byte length inlined into one `paste` payload.
---
--- Raised from 4 KB to 64 KB (recorder PRD §4.3), matching `doc.open`'s existing
--- ceiling. A `paste` event is NOT duplicated by a `doc.change`, so anything dropped
--- here is dropped from reconstruction AND from the paste heuristics for good — which
--- made a pasted solution above 4 KB, the single most load-bearing detection case in
--- the product, invisible.
---
--- Threshold change only — `content` is an optional field, so old and new analyzers
--- interoperate in both directions and `format_version` is NOT bumped.
---
--- Deliberately duplicated in events/external_change_content.lua rather than shared:
--- these two modules are independent faithful ports of separate TS files and the
--- repo's module isolation convention keeps them that way. Both must move together.
M.MAX_INLINE_BYTES = 64 * 1024
M.HEAD_TAIL_BYTES = 512

--- Decode a UTF-8 string into a list of codepoints, each carrying its byte
--- span in `text`. Malformed/truncated sequences fall back to treating the
--- offending byte as a single (Latin-1-ish) codepoint rather than raising,
--- since this is a best-effort preview helper, not a validator.
--- @param text string
--- @return table[] { {byte_start = integer, byte_len = integer, cp = integer}, ... }
local function decode_utf8(text)
  local codepoints = {}
  local n = #text
  local i = 1
  while i <= n do
    local b1 = text:byte(i)
    local cp, len

    if b1 < 0x80 then
      cp, len = b1, 1
    elseif b1 >= 0xF0 and b1 <= 0xF7 and i + 3 <= n then
      local b2, b3, b4 = text:byte(i + 1), text:byte(i + 2), text:byte(i + 3)
      cp = ((b1 % 0x08) * 0x40000) + ((b2 % 0x40) * 0x1000) + ((b3 % 0x40) * 0x40) + (b4 % 0x40)
      len = 4
    elseif b1 >= 0xE0 and b1 <= 0xEF and i + 2 <= n then
      local b2, b3 = text:byte(i + 1), text:byte(i + 2)
      cp = ((b1 % 0x10) * 0x1000) + ((b2 % 0x40) * 0x40) + (b3 % 0x40)
      len = 3
    elseif b1 >= 0xC0 and b1 <= 0xDF and i + 1 <= n then
      local b2 = text:byte(i + 1)
      cp = ((b1 % 0x20) * 0x40) + (b2 % 0x40)
      len = 2
    else
      -- Invalid lead byte or truncated sequence: treat as one raw byte.
      cp, len = b1, 1
    end

    codepoints[#codepoints + 1] = { byte_start = i, byte_len = len, cp = cp }
    i = i + len
  end
  return codepoints
end

--- UTF-16 code-unit cost of a single Unicode codepoint: 1 for BMP
--- (<= U+FFFF), 2 for astral (surrogate pair).
local function utf16_units(cp)
  if cp <= 0xFFFF then
    return 1
  end
  return 2
end

--- Longest prefix of `text` whose cumulative UTF-16-unit cost is <= limit,
--- never splitting a codepoint.
local function head_slice(codepoints, text, limit)
  local units = 0
  local end_byte = 0
  for _, c in ipairs(codepoints) do
    local u = utf16_units(c.cp)
    if units + u > limit then
      break
    end
    units = units + u
    end_byte = c.byte_start + c.byte_len - 1
  end
  return text:sub(1, end_byte)
end

--- Longest suffix of `text` whose cumulative UTF-16-unit cost is <= limit,
--- never splitting a codepoint.
local function tail_slice(codepoints, text, limit)
  local units = 0
  local start_byte = #text + 1
  for i = #codepoints, 1, -1 do
    local c = codepoints[i]
    local u = utf16_units(c.cp)
    if units + u > limit then
      break
    end
    units = units + u
    start_byte = c.byte_start
  end
  return text:sub(start_byte)
end

--- Build the payload fields for a `paste` event.
---
--- `length` is the UTF-8 byte length of `text` (`#text`, not a codepoint
--- or char count). `sha256` is the hex sha256 digest of the full text,
--- always present regardless of length. Either `content` is set (length
--- <= MAX_INLINE_BYTES) or `content_head` + `content_tail` are set
--- (length > MAX_INLINE_BYTES), never both.
--- @param text string
--- @return table fields
function M.build_paste_payload(text)
  local byte_length = #text
  local hash_hex = sha256.hex(text)

  if byte_length <= M.MAX_INLINE_BYTES then
    return {
      length = byte_length,
      sha256 = hash_hex,
      content = text,
    }
  end

  local codepoints = decode_utf8(text)
  return {
    length = byte_length,
    sha256 = hash_hex,
    content_head = head_slice(codepoints, text, M.HEAD_TAIL_BYTES),
    content_tail = tail_slice(codepoints, text, M.HEAD_TAIL_BYTES),
  }
end

return M
