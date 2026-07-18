--- external_change_detector — pure comparison of expected vs on-disk content.
--- Called from the doc.save path (doc_wiring) to detect external edits.
---
--- PRD §4.5: "When a doc.save fires, compute the on-disk sha256 and compare
--- it to our expected hash."
---
--- IMPORTANT: This function does NOT mutate `expected_ec`. The caller is
--- responsible for calling `expected_ec.reset(on_disk_content)` after
--- recording the fs.external_change event so that subsequent edits chain
--- from reality (CLAUDE.md + PRD §4.5).
---
--- DIRECTION (the whole point of this module): `old_hash` is always the
--- EXPECTED (what the editor believed) hash; `new_hash` is always the
--- ACTUAL on-disk hash. Never swap these.
---
--- Faithful port of the monorepo's external-change-detector.ts.
--- PURE: no Neovim editor API; only provenance.core.sha256.
local sha256 = require("provenance.core.sha256")

local M = {}

--- Count UTF-16 code units a UTF-8 string would decode to (matches JS
--- string .length exactly): 1 per BMP codepoint (<= 0xFFFF), 2 per astral
--- codepoint (>= 0x10000, encoded as a surrogate pair in UTF-16).
--- @param s string  UTF-8 byte string
--- @return integer
local function utf16_len(s)
  local len = 0
  local i = 1
  local n = #s
  while i <= n do
    local b = s:byte(i)
    local cp, size
    if b < 0x80 then
      cp, size = b, 1
    elseif b >= 0xF0 then
      cp = b % 0x08
      size = 4
    elseif b >= 0xE0 then
      cp = b % 0x10
      size = 3
    elseif b >= 0xC0 then
      cp = b % 0x20
      size = 2
    else
      -- Stray continuation byte (malformed UTF-8): treat as one unit so we
      -- never throw on documented inputs.
      cp, size = b, 1
    end

    for k = 1, size - 1 do
      local cb = s:byte(i + k)
      if cb == nil or cb < 0x80 or cb >= 0xC0 then
        -- Truncated/malformed sequence: bail out to single-byte handling.
        cp, size = b, 1
        break
      end
      cp = cp * 0x40 + (cb % 0x40)
    end

    len = len + (cp >= 0x10000 and 2 or 1)
    i = i + size
  end
  return len
end

--- Compare the on-disk content of a saved file against the in-memory
--- expected content model.
---
--- @param expected_ec table  ExpectedContent (has .hash() and .get_content())
--- @param on_disk_content string  actual content read from disk after save
--- @return table  { kind = "clean_save", new_hash } or
---                 { kind = "external_change", old_hash, new_hash, diff_size }
---
--- diff_size is an approximation: abs(utf16_len(on_disk_content) -
--- utf16_len(expected_ec.get_content())). A real diff algorithm (LCS/Myers)
--- is out of scope; this only populates the diff_size field in
--- FsExternalChangePayload and gives the analyzer a rough sense of how much
--- the file changed. For whole-file replacements the value is meaningful;
--- for small in-place edits it may be 0 even when content diverged
--- (same length, different bytes) — a documented limitation.
function M.compare_saved_content(expected_ec, on_disk_content)
  local actual_hash = sha256.hex(on_disk_content)
  local expected_hash = expected_ec.hash()

  if actual_hash == expected_hash then
    return { kind = "clean_save", new_hash = actual_hash }
  end

  local diff_size = math.abs(utf16_len(on_disk_content) - utf16_len(expected_ec.get_content()))

  return {
    kind = "external_change",
    old_hash = expected_hash,
    new_hash = actual_hash,
    diff_size = diff_size,
  }
end

return M
