--- Bundle manifest — model, shape validation, ed25519 signing.
--- Mirrors log-core's BundleManifest builder + validateBundleManifestShape and
--- the "sign the entire canonicalized manifest" convention: the exact
--- canonical_json string produced here is what gets persisted to
--- manifest.json (never re-serialized) and what the signature covers.
---
--- `build()` takes a plain snake_case description of the manifest (the shape
--- a sealed BundleManifest / a decoded fixture already has) and produces the
--- json value-model (core/json) form — arrays tagged via json.array, nulls
--- as json.NULL — ready for to_canonical()/sign(). `validate_shape()` is the
--- opposite direction: it accepts an arbitrary already-decoded JSON value
--- (e.g. vim.json.decode output, where JSON null becomes vim.NIL and arrays
--- are plain sequence tables) and checks it matches the BundleManifest shape
--- without requiring json-value-model tagging.
local json = require("provenance.core.json")
local result = require("provenance.core.result")
local ed25519 = require("provenance.core.ed25519")

local M = {}

-- Treat both Lua nil and vim.json.decode's null sentinel as "no value" —
-- build() may be fed either plain builder input or a decoded fixture.
local function is_null(v)
  return v == nil or v == vim.NIL
end

local function is_nonempty_string(v)
  return type(v) == "string" and v ~= ""
end

local function is_hex64(v)
  return type(v) == "string" and #v == 64 and v:match("^[0-9a-f]+$") ~= nil
end

--- Build the json value-model BundleManifest from a plain snake_case
--- description. `submission_files` is only read (and only emitted) when
--- format_version is "1.1"; it is omitted entirely for "1.0".
--- @param input table
--- @return table  manifest_value, ready for to_canonical()/sign()
function M.build(input)
  local m = {
    format_version = input.format_version,
    assignment_id = input.assignment_id,
    semester = input.semester,
    extension_hash = input.extension_hash,
    sessions = json.array({}),
  }

  local sessions = input.sessions or {}
  for i = 1, #sessions do
    local s = sessions[i]
    m.sessions[i] = {
      session_id = s.session_id,
      prev_session_id = is_null(s.prev_session_id) and json.NULL or s.prev_session_id,
      slog_sha256 = s.slog_sha256,
      meta_sha256 = s.meta_sha256,
    }
  end

  if input.format_version == "1.1" then
    m.submission_files = json.array({})
    local files = input.submission_files or {}
    for i = 1, #files do
      local f = files[i]
      m.submission_files[i] = {
        path = f.path,
        status = f.status,
        sha256 = (f.status == "missing" or is_null(f.sha256)) and json.NULL or f.sha256,
      }
    end
  end

  return m
end

--- The exact string that gets signed and written to manifest.json.
--- @param manifest_value table
--- @return string
function M.to_canonical(manifest_value)
  return json.canonicalize(manifest_value)
end

--- Validate that `value` (any already-decoded JSON value — vim.json.decode
--- output or a plain builder-shaped table) matches the BundleManifest shape.
--- Mirrors log-core's validateBundleManifestShape. Never throws.
--- @param value any
--- @return table  { ok = true, value } | { ok = false, error = { kind, field? } }
function M.validate_shape(value)
  local ok, res = pcall(function()
    if type(value) ~= "table" then
      return result.err({ kind = "not_object" })
    end

    local version = value.format_version
    if version ~= "1.0" and version ~= "1.1" then
      return result.err({ kind = "wrong_version", field = "format_version" })
    end

    for _, field in ipairs({ "assignment_id", "semester", "extension_hash" }) do
      local v = value[field]
      if is_null(v) then
        return result.err({ kind = "missing_field", field = field })
      end
      if not is_nonempty_string(v) then
        return result.err({ kind = "invalid_field", field = field })
      end
    end
    if not is_hex64(value.extension_hash) then
      return result.err({ kind = "invalid_field", field = "extension_hash" })
    end

    local sessions = value.sessions
    if is_null(sessions) or type(sessions) ~= "table" then
      return result.err({ kind = "missing_field", field = "sessions" })
    end
    for i = 1, #sessions do
      local s = sessions[i]
      if type(s) ~= "table" then
        return result.err({ kind = "invalid_field", field = "sessions" })
      end
      if not is_nonempty_string(s.session_id) then
        return result.err({ kind = "invalid_field", field = "session_id" })
      end
      if not is_null(s.prev_session_id) and not is_nonempty_string(s.prev_session_id) then
        return result.err({ kind = "invalid_field", field = "prev_session_id" })
      end
      if not is_hex64(s.slog_sha256) then
        return result.err({ kind = "invalid_field", field = "slog_sha256" })
      end
      if not is_hex64(s.meta_sha256) then
        return result.err({ kind = "invalid_field", field = "meta_sha256" })
      end
    end

    if version == "1.1" then
      local files = value.submission_files
      if is_null(files) or type(files) ~= "table" then
        return result.err({ kind = "missing_field", field = "submission_files" })
      end
      for i = 1, #files do
        local f = files[i]
        if type(f) ~= "table" then
          return result.err({ kind = "invalid_field", field = "submission_files" })
        end
        if not is_nonempty_string(f.path) then
          return result.err({ kind = "invalid_field", field = "path" })
        end
        if f.status ~= "present" and f.status ~= "missing" then
          return result.err({ kind = "invalid_field", field = "status" })
        end
        if f.status == "present" then
          if not is_hex64(f.sha256) then
            return result.err({ kind = "invalid_field", field = "sha256" })
          end
        else -- "missing"
          if not is_null(f.sha256) then
            return result.err({ kind = "invalid_field", field = "sha256" })
          end
        end
      end
    end

    return result.ok(value)
  end)
  if not ok then
    return result.err({ kind = "invalid_field" })
  end
  return res
end

--- Sign the canonicalized manifest. Caller persists canonical_json verbatim
--- to manifest.json and signature_hex to manifest.sig.
--- @param manifest_value table
--- @param signing_priv32 string  32-byte raw ed25519 private key (seed)
--- @return table  { canonical_json, signature_hex }
function M.sign(manifest_value, signing_priv32)
  local canonical_json = M.to_canonical(manifest_value)
  local signature_hex = ed25519.to_hex(ed25519.sign(canonical_json, signing_priv32))
  return { canonical_json = canonical_json, signature_hex = signature_hex }
end

--- @param canonical_json string
--- @param sig_hex string
--- @param pubkey_hex string
--- @return boolean  never throws; false on any malformed input
function M.verify_sig(canonical_json, sig_hex, pubkey_hex)
  local ok, verified = pcall(function()
    if type(sig_hex) ~= "string" or not sig_hex:match("^[0-9a-f]+$") then return false end
    return ed25519.verify(ed25519.from_hex(sig_hex), canonical_json, pubkey_hex)
  end)
  if not ok then return false end
  return verified == true
end

return M
