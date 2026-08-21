--- build_recorder_context: builds the session.start payload (SessionStartPayload).
--- Mirrors log-core's buildRecorderContext (recorder-context.ts). Pure(ish)
--- transform — every environment value is injectable via `env` for
--- deterministic tests.
local core_sha256 = require("provenance.core.sha256")
local core_json = require("provenance.core.json")
local recorder_context = require("provenance.recorder.session.recorder_context")

local FIXED_ENV = {
  uuid = function() return "11111111-1111-4111-8111-111111111111" end,
  hostname = "host",
  username = "alice",
  nvim_version = "0.12.1",
  platform = "Darwin",
  recorder_version = "0.1.0",
}

local MANIFEST = {
  assignment_id = "hw3",
  semester = "fa25",
  sig = string.rep("ab", 64), -- 128 hex chars
}

describe("build_recorder_context", function()
  it("builds the exact SessionStartPayload shape with a fixed env", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = "prev-uuid",
      session_pubkey_hex = "deadbeef",
      env = FIXED_ENV,
    })

    assert.equals("1.0", payload.format_version)
    assert.equals("11111111-1111-4111-8111-111111111111", payload.session_id)
    assert.equals("prev-uuid", payload.prev_session_id)
    assert.same({ id = "hw3", semester = "fa25" }, payload.assignment)
    assert.equals(MANIFEST.sig, payload.manifest_sig)
    assert.equals(
      core_sha256.hex("host:alice:11111111-1111-4111-8111-111111111111"),
      payload.machine_id
    )
    assert.same({ version = "0.12.1", commit = "", platform = "Darwin" }, payload.vscode)
    assert.same(
      { version = "0.1.0", extension_id = "com.provenance.recorder.nvim" },
      payload.recorder
    )
    assert.equals("deadbeef", payload.session_pubkey)
  end)

  it("sets vscode.commit to the empty string", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
      env = FIXED_ENV,
    })
    assert.equals("", payload.vscode.commit)
  end)

  it("hardcodes recorder.extension_id to the pinned producer id", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
      env = FIXED_ENV,
    })
    assert.equals("com.provenance.recorder.nvim", payload.recorder.extension_id)
  end)

  it("computes a deterministic machine_id from injected hostname/username/session_id", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
      env = FIXED_ENV,
    })
    local expected = core_sha256.hex("host:alice:11111111-1111-4111-8111-111111111111")
    assert.equals(expected, payload.machine_id)
  end)

  it("falls back to 'unknown' username when env.username absent and $USER/$USERNAME unset", function()
    local saved_user = vim.env.USER
    local saved_username = vim.env.USERNAME
    vim.env.USER = nil
    vim.env.USERNAME = nil

    local ok, payload = pcall(recorder_context.build_recorder_context, {
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
      env = {
        uuid = FIXED_ENV.uuid,
        hostname = "host",
        -- username intentionally omitted
        nvim_version = "0.12.1",
        platform = "Darwin",
        recorder_version = "0.1.0",
      },
    })

    vim.env.USER = saved_user
    vim.env.USERNAME = saved_username

    assert.is_true(ok)
    local expected = core_sha256.hex("host:unknown:11111111-1111-4111-8111-111111111111")
    assert.equals(expected, payload.machine_id)
  end)

  it("sets prev_session_id to core.json.NULL when prev_session_id is nil, and canonicalizes to null", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
      env = FIXED_ENV,
    })

    assert.equals(core_json.NULL, payload.prev_session_id)

    local canonical = core_json.canonicalize(payload)
    assert.is_truthy(canonical:find('"prev_session_id":null', 1, true))
  end)

  it("uses the given prev_session_id string verbatim when provided", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = "prev-uuid",
      session_pubkey_hex = nil,
      env = FIXED_ENV,
    })
    assert.equals("prev-uuid", payload.prev_session_id)
  end)

  it("uses the given session_pubkey_hex when provided", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = "cafebabe",
      env = FIXED_ENV,
    })
    assert.equals("cafebabe", payload.session_pubkey)
  end)

  it("defaults session_pubkey to the empty string when session_pubkey_hex is nil", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
      env = FIXED_ENV,
    })
    assert.equals("", payload.session_pubkey)
  end)

  it("generates a real uuid v4 session_id when env.uuid is not injected", function()
    local payload = recorder_context.build_recorder_context({
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
      env = {
        hostname = "host",
        username = "alice",
        nvim_version = "0.12.1",
        platform = "Darwin",
        recorder_version = "0.1.0",
      },
    })
    assert.is_truthy(
      payload.session_id:match(
        "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-[89ab]%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"
      )
    )
  end)

  it("uses defaults for hostname/nvim_version/platform/recorder_version when env is absent entirely", function()
    local ok, payload = pcall(recorder_context.build_recorder_context, {
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = nil,
    })
    assert.is_true(ok)
    assert.equals("1.0", payload.format_version)
    assert.is_string(payload.machine_id)
    assert.equals(64, #payload.machine_id)
  end)
end)

--- session.start 2.0 (program spec §5). Additive: `manifest` and `host` are new,
--- everything 1.x readers rely on is retained unchanged.
describe("build_recorder_context session.start 2.0", function()
  local core_manifest = require("provenance.core.manifest")

  local function this_file_dir()
    local source = debug.getinfo(1, "S").source
    local path = source:match("^@(.*)$") or source
    return vim.fn.fnamemodify(path, ":h")
  end

  local function read(path)
    return table.concat(vim.fn.readfile(path), "\n")
  end

  local fixtures = this_file_dir() .. "/../fixtures/"
  local legacy_manifest = core_manifest.parse(read(fixtures .. "legacy-manifest-v1.json")).value
  local v2_manifest = core_manifest.parse(read(fixtures .. "dev-manifest-v2.json")).value

  local function build(manifest)
    return recorder_context.build_recorder_context({
      manifest = manifest,
      session_pubkey_hex = "deadbeef",
      env = FIXED_ENV,
    })
  end

  it("emits the host block with editor=neovim and an empty editor_build", function()
    -- Neovim has no build-commit concept; the spec explicitly permits "".
    assert.same({
      editor = "neovim",
      editor_version = "0.12.1",
      editor_build = "",
      platform = "Darwin",
    }, build(v2_manifest).host)
  end)

  it("retains manifest_sig, the vscode block and the payload format_version", function()
    -- 1.x readers must keep working: `host` is additive, not a replacement yet.
    local payload = build(v2_manifest)
    assert.equals("1.0", payload.format_version)
    assert.equals(v2_manifest.sig, payload.manifest_sig)
    assert.same({ version = "0.12.1", commit = "", platform = "Darwin" }, payload.vscode)
  end)

  it("does NOT emit an identity block", function()
    -- Enrollment keys are sub-project S2 and do not exist yet. The field is
    -- optional precisely so this can land first; emitting an empty or invented
    -- one would be a claim the recorder cannot back.
    assert.is_nil(build(v2_manifest).identity)
    assert.is_nil(build(legacy_manifest).identity)
  end)

  it("carries the FULL 2.0 manifest, course_cert and policy included", function()
    local m = build(v2_manifest).manifest
    assert.equals("2.0", m.format_version)
    assert.equals("dev-course", m.course_id)
    assert.equals("test", m.assignment_id)
    assert.equals("dev", m.semester)
    assert.equals("solo", m.collaboration)
    assert.equals("bundle", m.submission)
    assert.equals("directory", m.scope)
    assert.equals(v2_manifest.sig, m.sig)
    assert.is_table(m.course_cert)
    assert.equals("dev-course", m.course_cert.course_id)
    assert.is_string(m.course_cert.root_sig)
    assert.is_table(m.policy)
    assert.is_true(m.policy.capture.selection_change)
  end)

  it("carries the manifest for a 1.x manifest too, with no 2.0 fields invented", function()
    -- This is what lets the analyzer apply the absence-vs-disabled rule: a 1.x
    -- manifest carries no policy, which reads as the default capture set.
    local m = build(legacy_manifest).manifest
    assert.equals("hw3", m.assignment_id)
    assert.equals("fa25", m.semester)
    assert.equals("2026-07-14T00:00:00Z", m.issued_at)
    assert.equals(legacy_manifest.sig, m.sig)
    assert.is_nil(m.course_cert)
    assert.is_nil(m.policy)
    assert.is_nil(m.course_id)
    assert.is_nil(m.collaboration)
    assert.is_nil(m.submission)
    assert.is_nil(m.scope)
  end)

  it("canonicalizes files_under_review as a JSON ARRAY, not an object", function()
    -- The payload is hashed into the chain, so an untagged list from a
    -- hand-built manifest would silently produce different bytes.
    local m = build(legacy_manifest).manifest
    assert.is_true(core_json.is_array(m.files_under_review))
    assert.is_not_nil(core_json.canonicalize(m):find('"files_under_review":%["src/main.py"'))

    local hand_built = build({
      assignment_id = "hw",
      semester = "fa25",
      issued_at = "2026-01-01T00:00:00Z",
      sig = string.rep("ab", 64),
      files_under_review = { "a.py" }, -- untagged plain list
    }).manifest
    assert.is_true(core_json.is_array(hand_built.files_under_review))
    assert.is_not_nil(core_json.canonicalize(hand_built):find('"files_under_review":%["a.py"%]'))
  end)

  it("ignores unknown keys on the source manifest", function()
    -- Fields are copied by name, so an unknown key can never silently enter the
    -- hashed chain.
    local m = build({
      assignment_id = "hw",
      semester = "fa25",
      issued_at = "2026-01-01T00:00:00Z",
      sig = string.rep("ab", 64),
      files_under_review = core_json.array({}),
      some_future_field = "ignored",
    }).manifest
    assert.is_nil(m.some_future_field)
  end)

  it("the emitted 2.0 manifest still verifies its own chain", function()
    -- The strongest statement that nothing was dropped or reshaped in transit:
    -- lift the manifest back out of the payload and re-walk the trust chain.
    local trust_keys = require("provenance.trust_keys")
    local emitted = build(v2_manifest).manifest
    local res = core_manifest.verify_chain(emitted, trust_keys.ROOT_PUBLIC_KEY_HEX)
    assert.is_true(res.ok, "emitted manifest must still chain: " .. vim.inspect(res.error or {}))
    assert.equals("dev-course", res.value.course_id)
  end)
end)

--- The three §5.6 CAPABILITY REPORTS. `git_capture`/`witness_capture` are
--- passed straight through by the caller (recording_session.lua derives
--- them); `file_scope` is resolved HERE, from `manifest.files_under_review`,
--- mirroring log-core's `resolveFileScope`.
describe("build_recorder_context session.start capability reports (collaboration spec §5.6)", function()
  local function build(extra)
    return recorder_context.build_recorder_context(vim.tbl_extend("force", {
      manifest = MANIFEST,
      prev_session_id = nil,
      session_pubkey_hex = "deadbeef",
      env = FIXED_ENV,
    }, extra or {}))
  end

  it("omits all three fields when the caller reports nothing and the manifest lists no files", function()
    local payload = build({})
    assert.is_nil(payload.git_capture)
    assert.is_nil(payload.witness_capture)
    -- An empty files_under_review still yields a RECORDED (not absent)
    -- file_scope: {watched=[], complete=true} is a real answer.
    assert.is_not_nil(payload.file_scope)
    assert.same({}, payload.file_scope.watched)
    assert.is_true(payload.file_scope.complete)
  end)

  it("passes git_capture through verbatim when supplied", function()
    for _, v in ipairs({ "available", "unavailable", "not_owned" }) do
      assert.equals(v, build({ git_capture = v }).git_capture)
    end
  end)

  it("passes witness_capture through verbatim when supplied", function()
    for _, v in ipairs({ "available", "unavailable" }) do
      assert.equals(v, build({ witness_capture = v }).witness_capture)
    end
  end)

  it("git_capture and witness_capture are independent: one can be reported without the other", function()
    local payload = build({ witness_capture = "available" })
    assert.is_nil(payload.git_capture)
    assert.equals("available", payload.witness_capture)
  end)

  it("OMIT never null: an unreported capability is absent from the canonical bytes, not `null`", function()
    local payload = build({ witness_capture = "available" })
    local canon = core_json.canonicalize(payload)
    assert.is_nil(canon:find("git_capture", 1, true))
    assert.is_not_nil(canon:find('"witness_capture":"available"', 1, true))
  end)

  it("resolves file_scope.watched from manifest.files_under_review, verbatim and in order", function()
    local m = vim.tbl_extend("force", {}, MANIFEST, { files_under_review = { "Solver.java", "src/Board.java" } })
    local payload = recorder_context.build_recorder_context({
      manifest = m,
      prev_session_id = nil,
      session_pubkey_hex = "deadbeef",
      env = FIXED_ENV,
    })
    assert.same({ "Solver.java", "src/Board.java" }, payload.file_scope.watched)
    assert.is_true(payload.file_scope.complete)
  end)

  it("EMPTY-WATCHED-ARRAY SERIALIZATION: file_scope.watched canonicalizes as [] when empty", function()
    local payload = build({})
    local canon = core_json.canonicalize(payload)
    assert.is_not_nil(canon:find('"watched":%[%]'))
    assert.is_nil(canon:find('"watched":{}', 1, true))
  end)

  it("MALFORMED-PATH REJECTION: an absolute path in files_under_review omits file_scope entirely", function()
    local m = vim.tbl_extend(
      "force",
      {},
      MANIFEST,
      { files_under_review = { "Solver.java", "/Users/student/Solver.java" } }
    )
    local payload = recorder_context.build_recorder_context({
      manifest = m,
      prev_session_id = nil,
      session_pubkey_hex = "deadbeef",
      env = FIXED_ENV,
    })
    assert.is_nil(payload.file_scope)
    assert.is_nil(core_json.canonicalize(payload):find("file_scope", 1, true))
  end)

  it("caps watched at FILE_SCOPE_MAX_ENTRIES and reports complete=false past the cap", function()
    local files = {}
    for i = 1, recorder_context.FILE_SCOPE_MAX_ENTRIES + 5 do
      files[i] = "f" .. i .. ".txt"
    end
    local m = vim.tbl_extend("force", {}, MANIFEST, { files_under_review = files })
    local payload = recorder_context.build_recorder_context({
      manifest = m,
      prev_session_id = nil,
      session_pubkey_hex = "deadbeef",
      env = FIXED_ENV,
    })
    assert.equals(recorder_context.FILE_SCOPE_MAX_ENTRIES, #payload.file_scope.watched)
    assert.is_false(payload.file_scope.complete)
    assert.equals("f1.txt", payload.file_scope.watched[1])
  end)

  it("resolve_file_scope is exposed directly and matches the manifest-driven path", function()
    local direct = recorder_context.resolve_file_scope({ "a.txt", "b.txt" })
    assert.same({ "a.txt", "b.txt" }, direct.watched)
    assert.is_true(direct.complete)
  end)
end)
