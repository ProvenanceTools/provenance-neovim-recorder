--- NDJSON serialize/parse for HashedEnvelope log entries.
--- The stored line is `json.canonicalize(HashedEnvelope)` + "\n". Parsing goes
--- through vim.json.decode (allowed builtin) then normalizes into the json
--- value model (Task 3) so a re-canonicalize round-trips byte-for-byte,
--- including the empty-[] vs empty-{} distinction.
local json = require("provenance.core.json")
local result = require("provenance.core.result")

local M = {}

local HEX64 = "^[0-9a-f][0-9a-f]" -- length checked separately
local function is_hex64(s)
  return type(s) == "string" and #s == 64 and s:match("^[0-9a-f]+$") ~= nil
end

-- Map a vim.json.decode result into the json value model.
local function normalize(v)
  if v == vim.NIL then return json.NULL end
  if type(v) ~= "table" then return v end
  if vim.tbl_isempty(v) then
    -- empty_dict() carries a metatable marking it an object; plain {} is []
    return getmetatable(v) and {} or json.array({})
  end
  if vim.islist(v) then
    local out = json.array({})
    for i = 1, #v do out[i] = normalize(v[i]) end
    return out
  end
  local out = {}
  for k, val in pairs(v) do out[k] = normalize(val) end
  return out
end

function M.serialize_entry(hashed)
  return json.canonicalize(hashed) .. "\n"
end

local function validate_shape(obj)
  if type(obj) ~= "table" or json.is_array(obj) then return "not an object" end
  if type(obj.seq) ~= "number" then return "seq" end
  if type(obj.t) ~= "number" then return "t" end
  if type(obj.wall) ~= "string" then return "wall" end
  if type(obj.kind) ~= "string" then return "kind" end
  if type(obj.data) ~= "table" or json.is_array(obj.data) then return "data" end
  if not is_hex64(obj.prev_hash) then return "prev_hash" end
  if not is_hex64(obj.hash) then return "hash" end
  return nil
end

function M.parse_entries(text)
  if text == "" then return result.ok({}) end
  local out = {}
  local line_no = 0
  for line in (text .. "\n"):gmatch("(.-)\n") do
    line_no = line_no + 1
    if line ~= "" then
      local ok, decoded = pcall(vim.json.decode, line, { luanil = { object = false, array = false } })
      if not ok then
        return result.err({ kind = "invalid_json", line = line_no, message = tostring(decoded) })
      end
      local obj = normalize(decoded)
      local bad = validate_shape(obj)
      if bad then
        return result.err({ kind = "invalid_shape", line = line_no, missing_field = bad })
      end
      out[#out + 1] = obj
    end
  end
  return result.ok(out)
end

return M
