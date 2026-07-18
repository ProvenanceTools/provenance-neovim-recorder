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
