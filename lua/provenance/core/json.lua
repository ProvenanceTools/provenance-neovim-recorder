--- JSON value model + JCS canonicalizer.
--- Reproduces log-core's canonical.ts, which is the `canonicalize` npm pkg v3:
--- JSON.stringify scalar semantics + code-unit key sort + no whitespace.
--- We construct all payloads ourselves, so arrays are explicitly tagged
--- (json.array) — never inferred from table shape — to avoid the empty-{}/[]
--- ambiguity. Objects are plain string-keyed tables; null is json.NULL.
local M = {}

M.NULL = setmetatable({}, { __tostring = function() return "null" end })

local ARRAY_MT = {}

--- Tag a list table as a JSON array. Returns the same table.
function M.array(t)
  return setmetatable(t or {}, ARRAY_MT)
end

function M.is_array(v)
  return type(v) == "table" and getmetatable(v) == ARRAY_MT
end

-- String escaping = JSON.stringify rules.
local SHORT = { ["\8"] = "\\b", ["\9"] = "\\t", ["\10"] = "\\n", ["\12"] = "\\f", ["\13"] = "\\r" }
local function escape_string(s)
  local out = s:gsub('[%z\1-\31"\\]', function(c)
    if c == '"' then return '\\"' end
    if c == "\\" then return "\\\\" end
    local short = SHORT[c]
    if short then return short end
    return string.format("\\u%04x", string.byte(c))
  end)
  return '"' .. out .. '"'
end

local function format_number(n)
  if n ~= n then error("NaN is not allowed") end
  if n == math.huge or n == -math.huge then error("Infinity is not allowed") end
  if n == 0 then return "0" end -- also collapses -0 → 0
  if n == math.floor(n) and math.abs(n) < 2 ^ 53 then
    return string.format("%d", n)
  end
  -- Non-integer path (defensive; real envelopes have no floats).
  local s = string.format("%.17g", n)
  -- Trim to shortest round-trip.
  for p = 1, 16 do
    local cand = string.format("%." .. p .. "g", n)
    if tonumber(cand) == n then s = cand; break end
  end
  return s
end

local canon -- forward decl
local function canon_object(t)
  local keys = {}
  for k in pairs(t) do
    if type(k) ~= "string" then error("object keys must be strings") end
    keys[#keys + 1] = k
  end
  table.sort(keys) -- bytewise == code-unit order for ASCII keys
  local parts = {}
  for _, k in ipairs(keys) do
    parts[#parts + 1] = escape_string(k) .. ":" .. canon(t[k])
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function canon_array(t)
  local parts = {}
  for i = 1, #t do
    parts[i] = canon(t[i])
  end
  return "[" .. table.concat(parts, ",") .. "]"
end

canon = function(v)
  local ty = type(v)
  if v == M.NULL then return "null" end
  if ty == "nil" then error("nil is not allowed (JSON has no undefined)") end
  if ty == "boolean" then return v and "true" or "false" end
  if ty == "number" then return format_number(v) end
  if ty == "string" then return escape_string(v) end
  if ty == "table" then
    if M.is_array(v) then return canon_array(v) end
    return canon_object(v)
  end
  error("cannot canonicalize value of type " .. ty)
end

function M.canonicalize(value)
  return canon(value)
end

return M
