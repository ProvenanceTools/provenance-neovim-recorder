--- Student identity commands (program spec §S2). Paste-based, by design.
---
--- **No network calls, ever** (recorder PRD NG2). The recorder never fetches a
--- credential and never phones a server. The flow is entirely offline:
---
---   1. `:ProvenanceEnrollmentRequest` prints the student's GLOBAL PUBLIC key.
---      They paste it into the institution's enrolment page.
---   2. The server issues a student credential and returns a JSON blob.
---   3. `:ProvenanceEnrollmentImport` takes that blob by paste and stores it.
---
--- Everything else — deriving the key, countersigning the session key, walking
--- the chain — is local, so the whole identity path works on a plane.
---
--- ## Identity is INSTITUTION-scoped now, so the request takes no course
---
--- A student has ONE key and ONE credential, obtained once, valid across every
--- course (`core/institution.lua`). `request` therefore needs no `course_id` and
--- no active workspace: it works before the student has any assignment open,
--- which is exactly the deadlock the 2.0 course-scoped design could not escape.
---
--- The LEGACY per-course request is kept as `request_course`, for a student who
--- still needs to re-derive a 2.0 key. `import_token` routes on the SIGNED
--- version, so both artifacts still import and the student never has to know
--- which kind they hold.
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

--- Print the student's GLOBAL PUBLIC key, creating the master secret on first
--- use. The public key is safe to send anywhere; the master secret it derives
--- from never leaves the machine.
---
--- Takes no course and consults no workspace — a 2.1 credential names no course.
--- @param opts table { store, key_cache? }
--- @return table { level, message }
function M.request(opts)
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
    keypair, derive_err = opts.key_cache.get_global(master.value)
  else
    local ok, kp = pcall(student_keys.derive_student_keypair, master.value)
    keypair = ok and kp or nil
    derive_err = (not ok) and tostring(kp) or nil
  end
  if type(keypair) ~= "table" then
    return err("Provenance: could not derive your student key: " .. tostring(derive_err))
  end

  return info(
    "Provenance enrollment request\n"
      .. "  student_pubkey: "
      .. keypair.public_key_hex
      .. "\n"
      .. "Paste that key into your institution's Provenance enrolment page. It\n"
      .. "will return a JSON credential; import it with :ProvenanceEnrollmentImport.\n"
      .. "One key, one credential, every course — you only do this once.\n"
      .. "NEVER paste your identity SECRET there (:ProvenanceIdentityExport)."
  )
end

--- LEGACY: print the student's PER-COURSE public key (identity 2.0).
---
--- Kept for a student who must re-derive a key an existing 2.0 token names.
--- New enrolments go through M.request.
--- @param opts table { store, key_cache?, course_id?, active_course_ids? }
--- @return table { level, message }
function M.request_course(opts)
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

--- Describe why one family's importer refused a paste.
local function describe_import_error(e, expected_version)
  if e.kind == "unsupported_format_version" then
    return "the "
      .. e.artifact
      .. " declares format_version '"
      .. e.format_version
      .. "', not "
      .. expected_version
  elseif e.kind == "course_id_mismatch" then
    return "the token is for " .. e.token_course_id .. " but the certificate is for " .. e.cert_course_id
  elseif e.kind == "institution_id_mismatch" then
    return "the credential is for "
      .. e.credential_institution_id
      .. " but the certificate is for "
      .. e.cert_institution_id
  elseif e.reason then
    return e.kind .. ": " .. tostring(e.reason)
  elseif e.message then
    return e.kind .. ": " .. tostring(e.message)
  end
  return e.kind
end

--- Import a pasted `{ enrollment, enrollment_cert }` blob, 2.0 or 2.1.
---
--- The store routes on the SIGNED `format_version` in the cert slot, never on
--- which fields are present, so the student never has to say which kind they
--- hold and a mislabelled paste cannot be read under the wrong rules.
--- @param opts table { store, raw_json }
--- @return table { level, message }
function M.import_token(opts)
  local raw = opts.raw_json
  if type(raw) ~= "string" or raw:match("^%s*$") then
    return warn("Provenance: nothing pasted; enrollment unchanged.")
  end

  local saved = opts.store.save_identity_artifact(raw)
  if not saved.ok then
    local e = saved.error
    local detail
    if e.kind == "current_2_1" then
      detail = describe_import_error(e.error, "2.1")
    elseif e.kind == "legacy_2_0" then
      detail = describe_import_error(e.error, "2.0")
    elseif e.kind == "unsupported_identity_version" then
      detail = "the certificate declares format_version '"
        .. e.format_version
        .. "', which is neither 2.0 nor 2.1"
    else
      detail = describe_import_error(e, "2.1")
    end
    return err("Provenance: identity artifact rejected (" .. detail .. "). Nothing was stored.")
  end

  if saved.value.identity_version == "2.1" then
    return info(
      "Provenance: identity imported for "
        .. saved.value.institution_id
        .. ". Every new session, in every course, will carry it."
    )
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
  local credential = opts.store.load_student_credential ~= nil
    and opts.store.load_student_credential()
    or nil

  local lines = {
    "Provenance identity",
    "  store:         " .. opts.store.path,
    "  master secret: " .. (has_secret and "present" or "not yet created"),
  }
  if type(credential) == "table" then
    -- The 2.1 credential DECIDES when present (see session_identity.lua), so it
    -- is reported first and named as the one in effect.
    lines[#lines + 1] = "  credential:    "
      .. credential.enrollment.institution_id
      .. " (student_ref "
      .. credential.enrollment.student_ref
      .. ")"
    lines[#lines + 1] = "                 in effect for every course"
  else
    lines[#lines + 1] = "  credential:    (none) — run :ProvenanceEnrollmentRequest"
  end
  if #courses == 0 then
    lines[#lines + 1] = "  legacy 2.0:    (none)"
  else
    lines[#lines + 1] = "  legacy 2.0:    " .. table.concat(courses, ", ")
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
      .. "Your keys re-derive identically, so existing credentials keep working.\n"
      .. "NEVER paste this into an enrolment page — it is your SECRET, not your "
      .. "public key. The leading marker exists so that page can refuse it."
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
