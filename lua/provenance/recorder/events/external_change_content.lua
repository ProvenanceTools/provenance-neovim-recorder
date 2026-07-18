--- external_change_content.lua — pure helper that fills the inline-content
--- fields on an fs.external_change payload.
---
--- Faithful port of the monorepo's events/external-change-content.ts.
--- Mirrors the paste-payload truncation pattern (recorder PRD §4.3 last
--- paragraph): inline the full text up to 4 KB, otherwise store head + tail
--- + size. Lets the analyzer reseed reconstruction after an external write
--- so the replay UI can show the post-change file (PRD §4.5 / §7.2).
---
--- PURE: no Neovim editor API, no core deps (chain/hash/signing). Byte
--- length is `#text` (Lua strings are byte arrays, same as
--- `Buffer.byteLength(text, 'utf8')`).
---
--- UTF-16-code-unit slicing (the port subtlety): the TS source uses JS
--- `text.slice(0, 512)` / `text.slice(-512)`, which count UTF-16 CODE UNITS,
--- not bytes and not codepoints. A BMP codepoint (<= U+FFFF) is 1 UTF-16
--- unit; an astral codepoint (>= U+10000, e.g. most emoji) is a surrogate
--- pair = 2 UTF-16 units. We decode `text` from UTF-8 into codepoints and
--- accumulate UTF-16-unit cost per codepoint to find the same boundary JS
--- would.
---
--- DELIBERATE DEVIATION: JS `slice` can legally cut a string BETWEEN the
--- two code units of an astral char's surrogate pair, producing a lone
--- (unpaired) surrogate in the result. Lua/UTF-8 has no representation for
--- a lone surrogate, so this port never splits an astral codepoint: it cuts
--- BEFORE it instead, keeping head/tail at <= 512 UTF-16 units (never more)
--- and always valid UTF-8. `new_content_head`/`new_content_tail` are
--- informational preview fields for the analyzer's replay UI — they are
--- never hashed or chain-verified — so this is analyzer-irrelevant. The
--- committed conformance fixture's large-multibyte case was deliberately
--- generated with an even-length run of 2-unit codepoints so the 512
--- boundary lands on a whole-codepoint boundary and Node's output and this
--- Lua output agree byte-for-byte.
local M = {}

M.MAX_INLINE_BYTES = 4096
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

--- Build the content fields for an fs.external_change payload.
---
--- `new_content_size` is the UTF-8 byte length of `text` (`#text`, not a
--- codepoint or char count). Either `new_content` is set (size <=
--- MAX_INLINE_BYTES) or `new_content_head` + `new_content_tail` are set
--- (size > MAX_INLINE_BYTES), never both.
--- @param text string
--- @return table fields
function M.build_external_change_content(text)
  local byte_length = #text

  if byte_length <= M.MAX_INLINE_BYTES then
    return {
      new_content_size = byte_length,
      new_content = text,
    }
  end

  local codepoints = decode_utf8(text)
  return {
    new_content_size = byte_length,
    new_content_head = head_slice(codepoints, text, M.HEAD_TAIL_BYTES),
    new_content_tail = tail_slice(codepoints, text, M.HEAD_TAIL_BYTES),
  }
end

return M
