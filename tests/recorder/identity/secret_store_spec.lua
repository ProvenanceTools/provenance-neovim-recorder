--- secret_store: the student master secret + per-course enrollment file.
--- Real vim.uv against real temp files — this module IS the storage seam, so
--- mocking the filesystem would test nothing.
local secret_store = require("provenance.recorder.identity.secret_store")
local core_enrollment = require("provenance.core.enrollment")
local student_keys = require("provenance.core.student_keys")
local ed25519 = require("provenance.core.ed25519")

local COURSE_ID = "berkeley-cs61b"
local COURSE_PRIV = ("\7"):rep(32)
local ENROLL_PRIV = ("\11"):rep(32)

local function pub_hex(priv)
  return ed25519.to_hex(ed25519.public_key_of(priv))
end

--- A well-formed { enrollment, enrollment_cert } pair for `course_id`.
local function make_blob(course_id, opts)
  opts = opts or {}
  local student_pubkey = opts.student_pubkey or ("5c"):rep(32)
  local cert = {
    format_version = "2.0",
    course_id = opts.cert_course_id or course_id,
    enrollment_pubkey = pub_hex(ENROLL_PRIV),
    valid_from = "2026-08-20",
    valid_until = "2027-01-15",
  }
  cert.course_sig = core_enrollment.sign_enrollment_cert(cert, COURSE_PRIV)

  local token = {
    format_version = "2.0",
    student_ref = "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    course_id = course_id,
    student_pubkey = student_pubkey,
    issued_at = "2026-09-01T00:00:00Z",
    expires_at = "2027-01-15",
  }
  token.enrollment_sig = core_enrollment.sign_enrollment_token(token, ENROLL_PRIV)

  return vim.json.encode(vim.tbl_extend("force", {
    enrollment = token,
    enrollment_cert = cert,
  }, opts.overrides or {}))
end

describe("secret_store", function()
  local tempdirs = {}

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function new_store()
    local dir = vim.fn.tempname()
    vim.fn.mkdir(dir, "p")
    table.insert(tempdirs, dir)
    return secret_store.new({ path = dir .. "/identity.json" }), dir
  end

  it("default_path is under stdpath('data'), never inside a project", function()
    -- The whole storage decision in one assertion: per-user, per-machine, and
    -- nowhere a git submission or seal's .provenance sweep can reach it.
    local path = secret_store.default_path()
    assert.is_not_nil(path:find(vim.fn.stdpath("data"), 1, true))
    assert.is_nil(path:find("/.provenance/", 1, true))
    assert.is_not_nil(path:find("/provenance/identity.json", 1, true))
  end)

  describe("master secret", function()
    it("load reports no_master_secret before anything is created", function()
      local store = new_store()
      local res = store.load_master_secret()
      assert.is_false(res.ok)
      assert.equals("no_master_secret", res.error.kind)
    end)

    it("load_or_create generates 32 bytes, persists them, and is stable", function()
      local store = new_store()
      local first = store.load_or_create_master_secret()
      assert.is_true(first.ok)
      assert.equals(32, #first.value)

      local second = store.load_or_create_master_secret()
      assert.is_true(second.ok)
      assert.equals(first.value, second.value, "the secret must not churn between calls")

      -- and it survives a fresh store object over the same file
      local reopened = secret_store.new({ path = store.path })
      assert.equals(first.value, reopened.load_master_secret().value)
    end)

    it("writes the file mode 0600 and its directory 0700", function()
      local store = new_store()
      store.load_or_create_master_secret()
      local st = vim.uv.fs_stat(store.path)
      assert.is_not_nil(st)
      -- Permissions ARE the protection here; there is no encryption.
      assert.equals(tonumber("600", 8), bit.band(st.mode, tonumber("777", 8)))
      local dir_st = vim.uv.fs_stat(store.path:match("(.*)/[^/]*$"))
      assert.equals(tonumber("700", 8), bit.band(dir_st.mode, tonumber("777", 8)))
    end)

    it("a CORRUPT stored secret is an error, never a silent regeneration", function()
      -- Regenerating would invalidate every token the student holds, and every
      -- archived bundle would carry an identity they can no longer reproduce.
      local store = new_store()
      store.load_or_create_master_secret()
      local original = store.export_master_secret().value

      vim.fn.writefile({ vim.json.encode({ master_secret = "nonsense", enrollments = {} }) }, store.path)

      for _, res in ipairs({ store.load_master_secret(), store.load_or_create_master_secret() }) do
        assert.is_false(res.ok)
        assert.equals("corrupt_master_secret", res.error.kind)
      end

      -- and the corrupt value is left on disk for hand recovery, not overwritten
      local raw = vim.json.decode(table.concat(vim.fn.readfile(store.path), "\n"))
      assert.equals("nonsense", raw.master_secret)
      assert.is_not.equals(original, raw.master_secret)
    end)

    it("export/import round-trips, and re-derives per-course keys identically", function()
      -- The new-machine story: existing enrollment tokens must keep working.
      local old_store = new_store()
      old_store.load_or_create_master_secret()
      local exported = old_store.export_master_secret()
      assert.is_true(exported.ok)
      assert.equals(64, #exported.value)

      local new_store_obj = new_store()
      assert.is_true(new_store_obj.import_master_secret(exported.value).ok)

      local a = student_keys.derive_course_keypair(old_store.load_master_secret().value, COURSE_ID)
      local b = student_keys.derive_course_keypair(new_store_obj.load_master_secret().value, COURSE_ID)
      assert.equals(a.public_key_hex, b.public_key_hex)
    end)

    it("import tolerates whitespace and uppercase, but rejects garbage without clobbering", function()
      local store = new_store()
      store.load_or_create_master_secret()
      local original = store.export_master_secret().value

      assert.is_true(store.import_master_secret("  " .. original:upper() .. "\n").ok)
      assert.equals(original, store.export_master_secret().value)

      local bad = store.import_master_secret("not a secret")
      assert.is_false(bad.ok)
      assert.equals("corrupt_master_secret", bad.error.kind)
      -- Overwriting on a typo would be unrecoverable.
      assert.equals(original, store.export_master_secret().value)
    end)
  end)

  describe("enrollment tokens", function()
    it("saves a valid blob under the course the token names, and loads it back", function()
      local store = new_store()
      local saved = store.save_enrollment(make_blob(COURSE_ID))
      assert.is_true(saved.ok)
      assert.equals(COURSE_ID, saved.value.course_id)

      local loaded = store.load_enrollment(COURSE_ID)
      assert.is_not_nil(loaded)
      assert.equals(COURSE_ID, loaded.enrollment.course_id)
      assert.equals("2.0", loaded.enrollment_cert.format_version)
      assert.same({ COURSE_ID }, store.enrolled_courses())
    end)

    it("keeps the master secret and tokens in ONE file, so a wipe reads as 'not enrolled'", function()
      local store = new_store()
      store.load_or_create_master_secret()
      store.save_enrollment(make_blob(COURSE_ID))

      vim.fn.delete(store.path)

      -- Both gone together: no half-state where a token exists but its key does not.
      assert.is_false(store.load_master_secret().ok)
      assert.is_nil(store.load_enrollment(COURSE_ID))
      assert.same({}, store.enrolled_courses())
    end)

    it("version-gates BEFORE shape, so a future 3.0 is a version error", function()
      local store = new_store()
      local blob = vim.json.decode(make_blob(COURSE_ID))
      blob.enrollment.format_version = "3.0"
      local res = store.save_enrollment(vim.json.encode(blob))
      assert.is_false(res.ok)
      assert.equals("unsupported_format_version", res.error.kind)
      assert.equals("token", res.error.artifact)
      assert.equals("3.0", res.error.format_version)
    end)

    it("rejects a token and cert naming different courses", function()
      -- Storing a pair that can never verify would leave the student "enrolled"
      -- while every session silently omitted an identity.
      local store = new_store()
      local res = store.save_enrollment(make_blob(COURSE_ID, { cert_course_id = "berkeley-cs61c" }))
      assert.is_false(res.ok)
      assert.equals("course_id_mismatch", res.error.kind)
      assert.is_nil(store.load_enrollment(COURSE_ID))
    end)

    it("rejects malformed JSON and malformed artifacts without throwing", function()
      local store = new_store()
      for _, raw in ipairs({ "{not json", "[]", '{"enrollment":{}}', "null" }) do
        local ok, res = pcall(store.save_enrollment, raw)
        assert.is_true(ok, "must not throw for: " .. raw)
        assert.is_false(res.ok)
      end
    end)

    it("load_enrollment returns nil for every failure — it is on the session-start path", function()
      local store = new_store()
      assert.is_nil(store.load_enrollment(COURSE_ID))

      store.save_enrollment(make_blob(COURSE_ID))
      vim.fn.writefile({ "{ corrupt" }, store.path)
      assert.is_nil(store.load_enrollment(COURSE_ID))
    end)

    it("clear_enrollment forgets one course and never touches the master secret", function()
      local store = new_store()
      store.load_or_create_master_secret()
      local secret = store.export_master_secret().value
      store.save_enrollment(make_blob(COURSE_ID))
      store.save_enrollment(make_blob("berkeley-cs61c"))

      store.clear_enrollment(COURSE_ID)

      assert.is_nil(store.load_enrollment(COURSE_ID))
      assert.is_not_nil(store.load_enrollment("berkeley-cs61c"))
      assert.equals(secret, store.export_master_secret().value)
    end)
  end)
end)
