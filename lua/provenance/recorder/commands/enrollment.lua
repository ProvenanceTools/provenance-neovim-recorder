--- Student identity commands (program spec §S2). Paste-based, by design.
---
--- **No network calls, ever** (recorder PRD NG2). The recorder never fetches a
--- token and never phones a server. The flow is entirely offline:
---
---   1. `:ProvenanceEnrollmentRequest [course_id]` prints the student's
---      per-course PUBLIC key. They send it to course staff by whatever channel
---      the course already uses.
---   2. Staff mint an enrollment token server-side and send back a JSON blob.
---   3. `:ProvenanceEnrollmentImport` takes that blob by paste and stores it.
---
--- Everything else — deriving the key, countersigning the session key, walking
--- the chain — is local, so the whole identity path works on a plane.
---
--- Each function returns `{ level, message }` rather than notifying directly, so
--- the logic is testable without capturing `vim.notify` (CLAUDE.md: test the
--- transform as a pure function, separately from the editor wiring).
local student_keys = require("provenance.core.student_keys")

local M = {}

local function info(message)
  return { level = vim.log.levels.INFO, message = message }
end

local function warn(message)
  return { level = vim.log.levels.WARN, message = message }
end

local function err(message)
  return { level = vim.log.levels.ERROR, message = message }
end

--- Resolve which course a command applies to.
--- @param course_id string|nil  explicit argument, if the student gave one
--- @param active_course_ids string[]  course ids of currently active 2.0 roots
--- @return string|nil course_id, table|nil failure
local function resolve_course(course_id, active_course_ids)
  if type(course_id) == "string" and course_id ~= "" then
    return course_id, nil
  end
  active_course_ids = active_course_ids or {}
  if #active_course_ids == 1 then
    return active_course_ids[1], nil
  end
  if #active_course_ids == 0 then
    return nil,
      err(
        "Provenance: no active Manifest 2.0 assignment, so the course is unknown. "
          .. "Pass it explicitly: :ProvenanceEnrollmentRequest <course_id>"
      )
  end
  return nil,
    err(
      "Provenance: several courses are active ("
        .. table.concat(active_course_ids, ", ")
        .. "). Pass one explicitly: :ProvenanceEnrollmentRequest <course_id>"
    )
end

--- Print the student's per-course PUBLIC key, creating the master secret on
--- first use. The public key is safe to send anywhere; the master secret it
--- derives from never leaves the machine.
--- @param opts table { store, key_cache?, course_id?, active_course_ids? }
--- @return table { level, message }
function M.request(opts)
  local course_id, failure = resolve_course(opts.course_id, opts.active_course_ids)
  if failure then
    return failure
  end

  local master = opts.store.load_or_create_master_secret()
  if not master.ok then
    return err(
      "Provenance: could not read or create the student identity secret ("
        .. tostring(master.error.kind)
        .. "). Store: "
        .. opts.store.path
    )
  end

  local keypair, derive_err
  if opts.key_cache then
    keypair, derive_err = opts.key_cache.get(master.value, course_id)
  else
    local ok, kp = pcall(student_keys.derive_course_keypair, master.value, course_id)
    keypair = ok and kp or nil
    derive_err = (not ok) and tostring(kp) or nil
  end
  if type(keypair) ~= "table" then
    return err("Provenance: could not derive a key for " .. course_id .. ": " .. tostring(derive_err))
  end

  return info(
    "Provenance enrollment request\n"
      .. "  course_id:      "
      .. course_id
      .. "\n"
      .. "  student_pubkey: "
      .. keypair.public_key_hex
      .. "\n"
      .. "Send both lines to course staff. They will send back a JSON token;\n"
      .. "import it with :ProvenanceEnrollmentImport"
  )
end

--- Import a pasted `{ enrollment, enrollment_cert }` blob.
--- @param opts table { store, raw_json }
--- @return table { level, message }
function M.import_token(opts)
  local raw = opts.raw_json
  if type(raw) ~= "string" or raw:match("^%s*$") then
    return warn("Provenance: nothing pasted; enrollment unchanged.")
  end

  local saved = opts.store.save_enrollment(raw)
  if not saved.ok then
    local e = saved.error
    local detail = e.kind
    if e.kind == "unsupported_format_version" then
      detail = "the " .. e.artifact .. " declares format_version '" .. e.format_version .. "', not 2.0"
    elseif e.kind == "course_id_mismatch" then
      detail = "the token is for " .. e.token_course_id .. " but the certificate is for " .. e.cert_course_id
    elseif e.reason then
      detail = e.kind .. ": " .. tostring(e.reason)
    elseif e.message then
      detail = e.kind .. ": " .. tostring(e.message)
    end
    return err("Provenance: enrollment token rejected (" .. detail .. "). Nothing was stored.")
  end

  return info(
    "Provenance: enrolled in "
      .. saved.value.course_id
      .. ". New sessions in that course will carry your identity."
  )
end

--- Show which courses have a stored enrollment, and where the store lives.
--- @param opts table { store }
--- @return table { level, message }
function M.status(opts)
  local courses = opts.store.enrolled_courses()
  local has_secret = opts.store.load_master_secret().ok

  local lines = {
    "Provenance identity",
    "  store:         " .. opts.store.path,
    "  master secret: " .. (has_secret and "present" or "not yet created"),
  }
  if #courses == 0 then
    lines[#lines + 1] = "  enrolled in:   (none)"
  else
    lines[#lines + 1] = "  enrolled in:   " .. table.concat(courses, ", ")
  end
  return info(table.concat(lines, "\n"))
end

--- Print the master secret for transfer to another machine.
--- @param opts table { store }
--- @return table { level, message }
function M.export_secret(opts)
  local exported = opts.store.export_master_secret()
  if not exported.ok then
    if exported.error.kind == "no_master_secret" then
      return warn(
        "Provenance: no student identity secret on this machine yet. "
          .. "Run :ProvenanceEnrollmentRequest first."
      )
    end
    return err("Provenance: could not read the identity secret (" .. tostring(exported.error.kind) .. ").")
  end
  return info(
    "Provenance student identity secret (KEEP PRIVATE — it signs as you in every course):\n"
      .. exported.value
      .. "\nOn the new machine run :ProvenanceIdentityImport and paste it. "
      .. "Your per-course keys re-derive identically, so existing tokens keep working."
  )
end

--- Adopt a master secret pasted from another machine.
--- @param opts table { store, raw }
--- @return table { level, message }
function M.import_secret(opts)
  local raw = opts.raw
  if type(raw) ~= "string" or raw:match("^%s*$") then
    return warn("Provenance: nothing pasted; identity secret unchanged.")
  end
  local imported = opts.store.import_master_secret(raw)
  if not imported.ok then
    -- A malformed paste leaves any existing secret untouched.
    return err(
      "Provenance: that does not look like an identity secret ("
        .. tostring(imported.error.reason or imported.error.kind)
        .. "). Nothing was changed."
    )
  end
  return info("Provenance: student identity secret imported. Existing enrollment tokens still apply.")
end

return M
