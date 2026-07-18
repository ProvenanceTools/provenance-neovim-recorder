--- Pure-Lua ZIP writer, STORE method (no compression) — no native
--- dependency, no shelling out to `zip` (design.md §3 keystone: pure-Lua,
--- vendored/original, zero native dependencies). This is non-crypto
--- formatting code (local headers + central directory + EOCD + CRC-32),
--- so it is written from scratch rather than vendored, per plan.
---
--- Sufficiency: the monorepo's golden bundle fixture
--- (tests/conformance/fixtures/golden-bundle.zip) uses STORE (method 0)
--- for every entry, and the analyzer reads bundles via JSZip, which
--- accepts STORE archives. A STORE-only writer is therefore adequate for
--- format parity — no DEFLATE implementation needed.
---
--- `lua/provenance/core/` scope: pure construction (`build`), zero
--- side effects, deterministic (no timestamps, no randomness). `write`
--- is the only I/O-touching entry point and lives here in `recorder/io/`
--- alongside atomic_write.lua, matching that module's fs idiom.
local bit = require("bit")
local band, bxor, rshift = bit.band, bit.bxor, bit.rshift

local M = {}

-- CRC-32 (IEEE 802.3, polynomial 0xEDB88320, reflected), pure Lua via the
-- LuaJIT `bit` library (same idiom as core/hkdf.lua and vendor/*.lua).
local CRC32_TABLE = {}
do
  for i = 0, 255 do
    local c = i
    for _ = 1, 8 do
      if band(c, 1) == 1 then
        c = bxor(0xEDB88320, rshift(c, 1))
      else
        c = rshift(c, 1)
      end
    end
    CRC32_TABLE[i] = c
  end
end

--- CRC-32 of `s`. Exposed (as `_crc32`) purely for unit testing against the
--- standard check vectors; not part of the public interface.
--- @param s string
--- @return integer
local function crc32(s)
  local crc = 0xFFFFFFFF
  for i = 1, #s do
    local byte = s:byte(i)
    crc = bxor(CRC32_TABLE[band(bxor(crc, byte), 0xFF)], rshift(crc, 8))
  end
  local result = bxor(crc, 0xFFFFFFFF)
  -- Bit ops (bit.bxor/band/rshift) return LuaJIT's signed 32-bit range
  -- (-2^31..2^31-1); normalize to the conventional unsigned CRC-32 value
  -- (0..2^32-1) so callers/tests can compare against the standard hex
  -- check values directly. The bit pattern is identical either way — le32
  -- below reinterprets via bit ops regardless of sign.
  if result < 0 then
    result = result + 4294967296
  end
  return result
end

local function le16(n)
  return string.char(band(n, 0xFF), band(rshift(n, 8), 0xFF))
end

local function le32(n)
  return string.char(
    band(n, 0xFF),
    band(rshift(n, 8), 0xFF),
    band(rshift(n, 16), 0xFF),
    band(rshift(n, 24), 0xFF)
  )
end

-- Fixed, deterministic MS-DOS date/time fields: no Date/os.time call
-- anywhere in this module (determinism; the analyzer ignores timestamps).
local DOS_TIME = 0
local DOS_DATE = 0x0021 -- 1980-01-01

--- Build a ZIP (STORE method) archive in memory from an ordered list of
--- `{ name = <archive path>, data = <bytes> }` entries. Pure: no I/O, no
--- clock/random reads, deterministic for identical input.
--- @param entries table[] ordered list of { name = string, data = string }
--- @return string archive_bytes
function M.build(entries)
  local local_parts = {}
  local central_parts = {}
  local offset = 0

  for _, entry in ipairs(entries) do
    local name = entry.name
    local data = entry.data
    local crc = crc32(data)
    local size = #data
    local name_len = #name

    local local_header = table.concat({
      le32(0x04034b50),
      le16(20), -- version needed to extract
      le16(0), -- general purpose bit flag
      le16(0), -- compression method: STORE
      le16(DOS_TIME),
      le16(DOS_DATE),
      le32(crc),
      le32(size), -- compressed size
      le32(size), -- uncompressed size
      le16(name_len),
      le16(0), -- extra field length
      name,
    })

    local_parts[#local_parts + 1] = local_header
    local_parts[#local_parts + 1] = data

    local central_header = table.concat({
      le32(0x02014b50),
      le16(20), -- version made by
      le16(20), -- version needed to extract
      le16(0), -- general purpose bit flag
      le16(0), -- compression method: STORE
      le16(DOS_TIME),
      le16(DOS_DATE),
      le32(crc),
      le32(size), -- compressed size
      le32(size), -- uncompressed size
      le16(name_len),
      le16(0), -- extra field length
      le16(0), -- file comment length
      le16(0), -- disk number start
      le16(0), -- internal file attributes
      le32(0), -- external file attributes
      le32(offset), -- relative offset of local header
      name,
    })
    central_parts[#central_parts + 1] = central_header

    offset = offset + #local_header + #data
  end

  local central_directory = table.concat(central_parts)
  local local_section_size = offset -- == total bytes of all local headers + data
  local central_dir_size = #central_directory

  local eocd = table.concat({
    le32(0x06054b50),
    le16(0), -- number of this disk
    le16(0), -- disk where central directory starts
    le16(#entries), -- central dir records on this disk
    le16(#entries), -- total central dir records
    le32(central_dir_size),
    le32(local_section_size), -- offset of start of central directory
    le16(0), -- ZIP file comment length
  })

  local parts = {}
  for _, p in ipairs(local_parts) do
    parts[#parts + 1] = p
  end
  parts[#parts + 1] = central_directory
  parts[#parts + 1] = eocd

  return table.concat(parts)
end

--- Persist `build(entries)` to `zip_path`. Raises on I/O failure (fresh
--- output file, not a signed/integrity-critical one — but atomic_write's
--- write-temp-then-rename is reused here for its clean raise-on-failure
--- behavior and unwritten-until-complete semantics).
--- @param zip_path string
--- @param entries table[]
--- @return boolean true on success
function M.write(zip_path, entries)
  local archive_bytes = M.build(entries)
  return require("provenance.recorder.io.atomic_write").atomic_write_file(zip_path, archive_bytes)
end

-- Exposed for unit testing against the standard CRC-32 check vectors only
-- (crc32("") == 0, crc32("123456789") == 0xCBF43926). Not part of the
-- public interface.
M._crc32 = crc32

return M
