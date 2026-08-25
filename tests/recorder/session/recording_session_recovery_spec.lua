--- recording_session.start — chain recovery wiring (Plan 8, Task 5).
--- Exercises the real seam: chain_recovery.recover_previous_session run
--- over the real vim.uv deps layer (uv_recovery_deps), BEFORE this
--- session's own artifacts exist, so it only ever sees a PRIOR session's
--- `.slog`. Mirrors recording_session_spec.lua's real-temp-dir approach —
--- prior `.slog` files are built with core.hash_chain the same way
--- chain_recovery_spec.lua / seal_spec.lua build chained slogs.
local recording_session = require("provenance.recorder.session.recording_session")
local core_clock = require("provenance.core.clock")
local core_ndjson = require("provenance.core.ndjson")
local core_json = require("provenance.core.json")
local core_hash_chain = require("provenance.core.hash_chain")
local core_envelope = require("provenance.core.envelope")

--- Track everything created by a test so it can be torn down afterward
--- (mirrors recording_session_spec.lua's new_scratch()).
local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, session = nil }

  function scratch.workspace()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    table.insert(scratch.dirs, dir)
    return dir
  end

  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
  end

  function scratch.teardown()
    if scratch.session then
      scratch.session.stop()
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
  end

  return scratch
end

local function read_all(path)
  local lines = vim.fn.readfile(path, "b")
  return table.concat(lines, "\n")
end

--- A minimal dev manifest with a real 128-hex signature (same convention as
--- recording_session_spec.lua / meta_writer_spec.lua / seal_spec.lua).
local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }
end

--- Build a real chained prior `.slog`'s raw NDJSON text (mirrors
--- chain_recovery_spec.lua's build_chain/serialize): session.start
--- (data.session_id = session_id), optionally followed by a clean
--- session.end. Omitting the session.end makes it DANGLING.
local function build_prior_slog_text(session_id, with_end)
  local e0 = core_hash_chain.chain_entry(
    core_hash_chain.GENESIS_PREV_HASH,
    core_envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", { session_id = session_id })
  )
  local entries = { e0 }
  if with_end then
    local e1 = core_hash_chain.chain_entry(
      e0.hash,
      core_envelope.new(1, 1000, "2026-01-01T00:00:01.000Z", "session.end", { reason = "seal" })
    )
    entries[#entries + 1] = e1
  end

  local lines = {}
  for _, e in ipairs(entries) do
    lines[#lines + 1] = core_ndjson.serialize_entry(e)
  end
  return table.concat(lines)
end

describe("recording_session.start — chain recovery wiring", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("clean start: no prior .slog -> session.start.prev_session_id is JSON null, no recovery event", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    local first = parsed.value[1]
    assert.equals("session.start", first.kind)
    assert.equals(core_json.NULL, first.data.prev_session_id)

    for _, e in ipairs(parsed.value) do
      assert.are_not.equals("recorder.recovered_from_corruption", e.kind)
    end
  end)

  it("dangling prior session links prev_session_id via real recovery over vim.uv", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.write_file(provenance_dir .. "/session-aaa.slog", build_prior_slog_text("crashed-id", false))

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    assert.is_true(parsed.ok)

    local first = parsed.value[1]
    assert.equals("session.start", first.kind)
    assert.equals("crashed-id", first.data.prev_session_id)
  end)

  it("a complete prior session is not linked (prev_session_id stays null)", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.write_file(provenance_dir .. "/session-aaa.slog", build_prior_slog_text("finished-id", true))

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    local first = parsed.value[1]
    assert.equals(core_json.NULL, first.data.prev_session_id)
  end)

  it("an explicit opts.prev_session_id override wins over the recovery decision", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.write_file(provenance_dir .. "/session-aaa.slog", build_prior_slog_text("crashed-id", false))

    scratch.session = recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
      prev_session_id = "explicit-override-id",
    })
    scratch.session.stop()

    local text = read_all(scratch.session.slog_path)
    local parsed = core_ndjson.parse_entries(text)
    local first = parsed.value[1]
    assert.equals("explicit-override-id", first.data.prev_session_id)
  end)

  it(
    "corrupt prior session is quarantined on disk and recorder.recovered_from_corruption "
      .. "follows session.start as seq 1",
    function()
      local workspace = scratch.workspace()
      local provenance_dir = workspace .. "/.provenance"
      vim.fn.mkdir(provenance_dir, "p")

      local bad_path = provenance_dir .. "/session-bad.slog"
      scratch.write_file(bad_path, "{not ndjson garbage")

      scratch.session = recording_session.start({
        workspace = workspace,
        provenance_dir = provenance_dir,
        manifest = dev_manifest(),
        clock = core_clock.fixed(0, 0),
      })
      scratch.session.stop()

      -- The original corrupt file is gone; a quarantine file exists in its
      -- place, named `<original>.corrupt-<ts>`.
      assert.is_nil(vim.uv.fs_stat(bad_path))

      local names = vim.fn.readdir(provenance_dir)
      local quarantined_name = nil
      for _, name in ipairs(names) do
        if name:match("^session%-bad%.slog%.corrupt%-") then
          quarantined_name = name
        end
      end
      assert.is_not_nil(quarantined_name)
      local quarantined_path = provenance_dir .. "/" .. quarantined_name
      assert.is_true(vim.uv.fs_stat(quarantined_path) ~= nil)

      local text = read_all(scratch.session.slog_path)
      local parsed = core_ndjson.parse_entries(text)
      assert.is_true(parsed.ok)
      assert.is_true(#parsed.value >= 2)

      assert.equals("session.start", parsed.value[1].kind)
      assert.equals(0, parsed.value[1].seq)
      assert.equals(core_json.NULL, parsed.value[1].data.prev_session_id)

      local second = parsed.value[2]
      assert.equals("recorder.recovered_from_corruption", second.kind)
      assert.equals(1, second.seq)
      assert.equals(quarantined_path, second.data.quarantined_path)

      local chain = require("provenance.core.chain_validator").validate_chain(parsed.value)
      assert.is_true(chain.ok)
    end
  )
end)

--- ===========================================================================
--- THE SHARED REPO, THROUGH THE REAL WIRING — decision-log bug 2
--- ===========================================================================
---
--- `chain_recovery`'s own spec pins the decision; this pins the WIRING, which
--- is where the fix could still be dead: recovery runs before this session has
--- a `session_id`, so the only thing that can answer "is this file mine?" is
--- the `student_ref` from `session.start.identity.enrollment` — and that
--- identity is built by `session_identity.build` several steps after recovery
--- used to run. Recovery had to move to AFTER identity resolves, and these
--- examples fail if it moves back or if the ref stops being threaded.
---
--- Everything below drives the real `recording_session.start` over a real
--- temp dir with a real, genuinely-signed enrollment — no `opts.recover`
--- injection — so a partner's file on disk is really left on disk.
local secret_store = require("provenance.recorder.identity.secret_store")
local core_enrollment = require("provenance.core.enrollment")
local student_keys = require("provenance.core.student_keys")
local ed25519 = require("provenance.core.ed25519")

describe("recording_session.start — chain recovery ownership wiring", function()
  local COURSE_ID = "berkeley-cs61b"
  local COURSE_PRIV = ("\7"):rep(32)
  local ENROLL_PRIV = ("\11"):rep(32)
  local MASTER_HEX = ("4a"):rep(32)
  local ALICE_REF = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
  local BOB_REF = "9a7b1c2d-3e4f-4a5b-8c9d-0e1f2a3b4c5d"

  local scratch
  local tempdirs = {}

  local function pub_hex(priv)
    return ed25519.to_hex(ed25519.public_key_of(priv))
  end

  -- ~6.3 ms of pure-Lua derivation, paid once for the whole describe rather
  -- than per example.
  local derived
  local function derived_keypair()
    if derived == nil then
      derived = student_keys.derive_course_keypair(ed25519.from_hex(MASTER_HEX), COURSE_ID)
    end
    return derived
  end

  local function course_cert()
    return {
      format_version = "2.0",
      course_id = COURSE_ID,
      course_pubkey = pub_hex(COURSE_PRIV),
    }
  end

  --- A 2.0 manifest whose `course_cert` is the identity trust anchor.
  local function manifest_2_0()
    return {
      format_version = "2.0",
      course_id = COURSE_ID,
      assignment_id = "hw3",
      semester = "fa25",
      issued_at = "2026-01-01T00:00:00Z",
      files_under_review = { "foo.txt" },
      collaboration = "pair",
      submission = "bundle",
      scope = "directory",
      course_cert = course_cert(),
      sig = ("ab"):rep(64),
    }
  end

  --- A store holding the fixed master secret and a genuinely-signed
  --- enrollment for ALICE_REF. Same construction as
  --- tests/recorder/identity/session_identity_spec.lua.
  local function enrolled_store()
    local dir = vim.fn.tempname()
    vim.fn.mkdir(dir, "p")
    table.insert(tempdirs, dir)
    local store = secret_store.new({ path = dir .. "/identity.json" })
    assert.is_true(store.import_master_secret(MASTER_HEX).ok)

    local cert = {
      format_version = "2.0",
      course_id = COURSE_ID,
      enrollment_pubkey = pub_hex(ENROLL_PRIV),
      valid_from = "2026-08-20",
      valid_until = "2027-01-15",
    }
    cert.course_sig = core_enrollment.sign_enrollment_cert(cert, COURSE_PRIV)

    local token = {
      format_version = "2.0",
      student_ref = ALICE_REF,
      course_id = COURSE_ID,
      student_pubkey = derived_keypair().public_key_hex,
      issued_at = "2026-09-01T00:00:00Z",
      expires_at = "2027-01-15",
    }
    token.enrollment_sig = core_enrollment.sign_enrollment_token(token, ENROLL_PRIV)

    assert.is_true(store.save_enrollment(vim.json.encode({
      enrollment = token,
      enrollment_cert = cert,
    })).ok)
    return store
  end

  --- A prior `.slog` whose session.start optionally names a contributor.
  --- `student_ref = nil` is a 1.x / pre-enrollment log: UNATTRIBUTED.
  local function prior_slog_text(session_id, student_ref, with_end)
    local data = { session_id = session_id }
    if student_ref ~= nil then
      data.identity = {
        enrollment = { student_ref = student_ref, course_id = COURSE_ID },
      }
    end
    local e0 = core_hash_chain.chain_entry(
      core_hash_chain.GENESIS_PREV_HASH,
      core_envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", data)
    )
    local entries = { e0 }
    if with_end then
      entries[#entries + 1] = core_hash_chain.chain_entry(
        e0.hash,
        core_envelope.new(1, 1000, "2026-01-01T00:00:01.000Z", "session.end", { reason = "seal" })
      )
    end
    local lines = {}
    for _, e in ipairs(entries) do
      lines[#lines + 1] = core_ndjson.serialize_entry(e)
    end
    return table.concat(lines)
  end

  --- A log whose FIRST LINE is a valid session.start naming `student_ref` and
  --- whose tail is damaged — a partner mid-write, or a half-finished checkout.
  --- This is the exact shape the old code renamed.
  local function damaged_slog_text(student_ref)
    return prior_slog_text("their-live-session", student_ref, false) .. "{truncated\n"
  end

  local function quarantine_files(dir)
    local found = {}
    for _, name in ipairs(vim.fn.readdir(dir)) do
      if name:find(".corrupt-", 1, true) then
        found[#found + 1] = name
      end
    end
    return found
  end

  local function start_enrolled(provenance_dir, workspace)
    return recording_session.start({
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = manifest_2_0(),
      clock = core_clock.fixed(0, 0),
      identity_store = enrolled_store(),
    })
  end

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  it("emits an identity, so the examples below are actually testing an ENROLLED recorder", function()
    -- Guard rail. Every assertion in this describe is meaningless if the
    -- identity silently fails to build, because an unattributed recorder
    -- reaches some of the same outcomes by a different route.
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.session = start_enrolled(provenance_dir, workspace)
    scratch.session.stop()

    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.is_true(parsed.ok)
    assert.equals(ALICE_REF, parsed.value[1].data.identity.enrollment.student_ref)
  end)

  it("leaves a partner's damaged .slog on disk, byte for byte, and does not link to it", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    -- Sorts after any `session-...` name this session mints, which on the old
    -- code is exactly what made it "the previous session".
    local partner_path = provenance_dir .. "/session-zzzz-partner.slog"
    local partner_bytes = damaged_slog_text(BOB_REF)
    scratch.write_file(partner_path, partner_bytes)

    scratch.session = start_enrolled(provenance_dir, workspace)
    scratch.session.stop()

    -- The partner's only record is still there, unmodified and unrenamed.
    assert.is_not_nil(vim.uv.fs_stat(partner_path))
    assert.equals(partner_bytes, read_all(partner_path))
    assert.same({}, quarantine_files(provenance_dir))

    -- And we did not claim their session as our predecessor.
    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.equals(core_json.NULL, parsed.value[1].data.prev_session_id)
    for _, e in ipairs(parsed.value) do
      assert.are_not.equals("recorder.recovered_from_corruption", e.kind)
    end
  end)

  it("an enrolled recorder leaves an UNATTRIBUTED damaged log alone", function()
    -- This is the example that fails the moment the student_ref stops being
    -- threaded from session_identity into recovery: with own_student_ref nil
    -- the recorder reads as unattributed, the file becomes eligible, and it
    -- gets renamed.
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    local mystery_path = provenance_dir .. "/session-zzzz-mystery.slog"
    local mystery_bytes = damaged_slog_text(nil)
    scratch.write_file(mystery_path, mystery_bytes)

    scratch.session = start_enrolled(provenance_dir, workspace)
    scratch.session.stop()

    assert.is_not_nil(vim.uv.fs_stat(mystery_path))
    assert.equals(mystery_bytes, read_all(mystery_path))
    assert.same({}, quarantine_files(provenance_dir))
  end)

  it("an enrolled recorder still recovers its OWN crash, past a partner's log", function()
    -- Crash recovery is what this module is FOR. An enrolled student whose own
    -- session died still gets the back-pointer, and gets it to their own
    -- session, not to whichever file sorted last.
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    scratch.write_file(
      provenance_dir .. "/session-aaaa-mine.slog",
      prior_slog_text("my-crashed-session", ALICE_REF, false)
    )
    local partner_path = provenance_dir .. "/session-zzzz-partner.slog"
    scratch.write_file(partner_path, prior_slog_text("their-session", BOB_REF, false))

    scratch.session = start_enrolled(provenance_dir, workspace)
    scratch.session.stop()

    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.equals("my-crashed-session", parsed.value[1].data.prev_session_id)
    assert.is_not_nil(vim.uv.fs_stat(partner_path))
  end)

  it("an enrolled recorder still quarantines its OWN corrupt log", function()
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")

    local mine_path = provenance_dir .. "/session-aaaa-mine.slog"
    scratch.write_file(mine_path, damaged_slog_text(ALICE_REF))

    scratch.session = start_enrolled(provenance_dir, workspace)
    scratch.session.stop()

    assert.is_nil(vim.uv.fs_stat(mine_path))
    assert.equals(1, #quarantine_files(provenance_dir))

    local parsed = core_ndjson.parse_entries(read_all(scratch.session.slog_path))
    assert.equals("recorder.recovered_from_corruption", parsed.value[2].kind)
  end)
end)
