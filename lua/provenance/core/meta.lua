--- Shape validator for the `.slog.meta` file (Plan 4 §meta; design.md).
--- Faithful Lua port of log-core's `validateMetaShape`
--- (packages/log-core/src/meta.ts): same field-check order, same error
--- kinds, same hex-length rules. The `.slog.meta` holds the session public
--- key, the encrypted session private key, and the signed checkpoints — the
--- real analyzer reads this file, so shape and field order must match
--- log-core exactly.
---
--- No I/O, no crypto verification here — shape only (mirrors meta.ts's own
--- scope: "No I/O here — types and validateMetaShape only"). Never throws.
local json = require("provenance.core.json")
local result = require("provenance.core.result")

local M = {}

local function is_nonempty_hex(v)
  return type(v) == "string" and v ~= "" and v:match("^[0-9a-f]+$") ~= nil
end

local function is_hex_64(v)
  return type(v) == "string" and #v == 64 and v:match("^[0-9a-f]+$") ~= nil
end

local function is_hex_128(v)
  return type(v) == "string" and #v == 128 and v:match("^[0-9a-f]+$") ~= nil
end

-- Array detection that works both on hand-built values (tagged via
-- `json.array`) and on raw `vim.json.decode` output (untagged): a decoded
-- empty JSON *object* carries a metatable (vim.empty_dict()-like), while a
-- decoded empty JSON *array* does not — the same ambiguity `core.json`'s
-- comment describes, resolved here the same way `manifest.lua`'s
-- `normalize()` resolves it, without mutating/copying the input.
local function is_array(v)
  if type(v) ~= "table" then
    return false
  end
  if json.is_array(v) then
    return true
  end
  if vim.tbl_isempty(v) then
    return getmetatable(v) == nil
  end
  return vim.islist(v)
end

-- True when `v` is not a plain JSON object: not a table, is the JSON-null
-- sentinel, or is (tagged/untagged) an array. Mirrors the TS check
-- `typeof x !== 'object' || x === null || Array.isArray(x)`.
local function is_not_object(v)
  return type(v) ~= "table" or v == json.NULL or is_array(v)
end

--- Validate that an unknown Lua value has the SlogMeta shape.
--- Does not verify crypto (signatures, ciphertext integrity, etc.).
--- @param value any
--- @return table  { ok = true, value = SlogMeta }
---              | { ok = false, error = { kind, field?, reason?, actual? } }
function M.validate_shape(value)
  local ok, res = pcall(function()
    if is_not_object(value) then
      return result.err({ kind = "not_object" })
    end

    local obj = value

    -- format_version
    if obj.format_version ~= "1.0" then
      return result.err({ kind = "wrong_version", actual = obj.format_version })
    end

    -- session_id
    if obj.session_id == nil then
      return result.err({ kind = "missing_field", field = "session_id" })
    end
    if type(obj.session_id) ~= "string" or obj.session_id == "" then
      return result.err({
        kind = "invalid_field",
        field = "session_id",
        reason = "must be a non-empty string",
      })
    end

    -- session_pubkey: 64 hex chars (32 bytes)
    local pubkey = obj.session_pubkey
    if not is_hex_64(pubkey) then
      if pubkey == nil then
        return result.err({ kind = "missing_field", field = "session_pubkey" })
      end
      return result.err({
        kind = "invalid_field",
        field = "session_pubkey",
        reason = "must be 64 lowercase hex chars (32 bytes)",
      })
    end

    -- encrypted_session_privkey
    local esp = obj.encrypted_session_privkey
    if is_not_object(esp) then
      if esp == nil then
        return result.err({ kind = "missing_field", field = "encrypted_session_privkey" })
      end
      return result.err({
        kind = "invalid_field",
        field = "encrypted_session_privkey",
        reason = "must be an object",
      })
    end

    if esp.algorithm ~= "xchacha20-poly1305-hkdf-sha256-v1" then
      if esp.algorithm == nil then
        return result.err({ kind = "missing_field", field = "encrypted_session_privkey.algorithm" })
      end
      return result.err({
        kind = "invalid_field",
        field = "encrypted_session_privkey.algorithm",
        reason = 'must be "xchacha20-poly1305-hkdf-sha256-v1"',
      })
    end

    for _, hex_field in ipairs({ "nonce", "ciphertext", "salt" }) do
      local v = esp[hex_field]
      if not is_nonempty_hex(v) then
        if v == nil then
          return result.err({
            kind = "missing_field",
            field = "encrypted_session_privkey." .. hex_field,
          })
        end
        return result.err({
          kind = "invalid_field",
          field = "encrypted_session_privkey." .. hex_field,
          reason = "must be a non-empty lowercase hex string",
        })
      end
    end

    if type(esp.info) ~= "string" or esp.info == "" then
      if esp.info == nil then
        return result.err({ kind = "missing_field", field = "encrypted_session_privkey.info" })
      end
      return result.err({
        kind = "invalid_field",
        field = "encrypted_session_privkey.info",
        reason = "must be a non-empty string",
      })
    end

    -- checkpoints: array
    local checkpoints = obj.checkpoints
    if not is_array(checkpoints) then
      if checkpoints == nil then
        return result.err({ kind = "missing_field", field = "checkpoints" })
      end
      return result.err({ kind = "invalid_field", field = "checkpoints", reason = "must be an array" })
    end

    for i = 0, #checkpoints - 1 do
      local cp = checkpoints[i + 1] -- 0-indexed field naming (mirrors the TS `for` loop), 1-indexed Lua access
      if type(cp) ~= "table" or cp == json.NULL then
        return result.err({
          kind = "invalid_field",
          field = "checkpoints[" .. i .. "]",
          reason = "must be an object",
        })
      end

      if type(cp.seq) ~= "number" then
        return result.err({
          kind = "invalid_field",
          field = "checkpoints[" .. i .. "].seq",
          reason = "must be a number",
        })
      end
      if not is_hex_64(cp.hash) then
        return result.err({
          kind = "invalid_field",
          field = "checkpoints[" .. i .. "].hash",
          reason = "must be 64 hex chars",
        })
      end
      if not is_hex_128(cp.sig) then
        return result.err({
          kind = "invalid_field",
          field = "checkpoints[" .. i .. "].sig",
          reason = "must be 128 hex chars (64 bytes)",
        })
      end
    end

    return result.ok(value)
  end)

  if not ok then
    return result.err({ kind = "not_object" })
  end
  return res
end

return M
