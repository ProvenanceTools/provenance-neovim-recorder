--- The rolling seal, write side. Real vim.uv against real temp-dir fixtures,
--- per CLAUDE.md's "real, focused" bar for editor-seam code.
---
--- The properties under test are the ones that make a rolling seal safe to
--- commit to git: it names itself after its own session, it is signed by that
--- session's key, it never touches the classic seal, it lands atomically, and
--- it claims finality on exactly the roll that is entitled to.
local writer = require("provenance.recorder.io.rolling_seal_writer")
local rolling = require("provenance.core.rolling_manifest")
local bundle = require("provenance.core.bundle")
local sha256 = require("provenance.core.sha256")
local ed25519 = require("provenance.core.ed25519")

local SESSION_ID = "33333333-3333-4333-8333-333333333333"
local OTHER_SESSION_ID = "44444444-4444-4444-8444-444444444444"
local PRIV = string.rep("\6", 32)
local OTHER_PRIV = string.rep("\7", 32)
local EXT_HASH = string.rep("1", 64)

local function read_all(path)
  return table.concat(vim.fn.readfile(path, "b"), "\n")
end

-- `contents` is split on newlines because vim.fn.writefile turns an embedded NL
-- inside a list item into a NUL byte — which would silently write bytes other
-- than the ones the assertions hash.
local function write_file(path, contents)
  vim.fn.writefile(vim.split(contents, "\n", { plain = true }), path, "b")
end

local function exists(path)
  return (vim.uv or vim.loop).fs_stat(path) ~= nil
end

describe("rolling_seal_writer", function()
  local tempdirs = {}
  local workspace, provenance_dir

  local function new_tempdir()
    local dir = vim.fn.tempname()
    vim.fn.mkdir(dir, "p")
    table.insert(tempdirs, dir)
    return dir
  end

  before_each(function()
    workspace = new_tempdir()
    provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    write_file(provenance_dir .. "/session-abc.slog", '{"seq":0}')
    write_file(provenance_dir .. "/session-abc.slog.meta", '{"session_id":"x"}')
    write_file(workspace .. "/present.java", "class Present {}")
  end)

  after_each(function()
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  local function roll(overrides)
    local opts = {
      provenance_dir = provenance_dir,
      session_id = SESSION_ID,
      prev_session_id = nil,
      slog_path = provenance_dir .. "/session-abc.slog",
      workspace = workspace,
      assignment_id = "proj2",
      semester = "fa26",
      files_under_review = { "present.java", "absent.java" },
      session_privkey = PRIV,
      extension_hash = EXT_HASH,
    }
    for k, v in pairs(overrides or {}) do
      opts[k] = v
    end
    return writer.write_rolling_seal(opts)
  end

  local function decoded_manifest()
    return vim.json.decode(read_all(provenance_dir .. "/" .. rolling.filenames(SESSION_ID).json))
  end

  -- --- naming ---------------------------------------------------------------

  it("writes manifest-<session_id>.json and .sig, and NOTHING else", function()
    local res = roll()
    assert.equals("written", res.kind)

    local names = rolling.filenames(SESSION_ID)
    assert.is_true(exists(provenance_dir .. "/" .. names.json))
    assert.is_true(exists(provenance_dir .. "/" .. names.sig))
    assert.equals(provenance_dir .. "/" .. names.json, res.manifest_path)
    assert.equals(provenance_dir .. "/" .. names.sig, res.sig_path)
  end)

  it("NEVER writes the classic manifest.json / manifest.sig", function()
    -- The classic seal is `commands/seal.lua`'s alone. A rolling roll that
    -- landed on those paths would overwrite a signed, already-submitted bundle
    -- with a single-session 1.2 manifest.
    roll()
    assert.is_false(exists(provenance_dir .. "/manifest.json"))
    assert.is_false(exists(provenance_dir .. "/manifest.sig"))
  end)

  it("leaves an EXISTING classic seal byte-for-byte untouched across many rolls", function()
    local classic_json = '{"format_version":"1.1","assignment_id":"proj2"}'
    local classic_sig = string.rep("ab", 64)
    write_file(provenance_dir .. "/manifest.json", classic_json)
    write_file(provenance_dir .. "/manifest.sig", classic_sig)
    local before_json = sha256.hex(read_all(provenance_dir .. "/manifest.json"))
    local before_sig = sha256.hex(read_all(provenance_dir .. "/manifest.sig"))

    for _ = 1, 5 do
      assert.equals("written", roll().kind)
    end
    assert.equals("written", roll({ final = true }).kind)

    assert.equals(before_json, sha256.hex(read_all(provenance_dir .. "/manifest.json")))
    assert.equals(before_sig, sha256.hex(read_all(provenance_dir .. "/manifest.sig")))
    assert.equals(classic_json, read_all(provenance_dir .. "/manifest.json"))
    assert.equals(classic_sig, read_all(provenance_dir .. "/manifest.sig"))
  end)

  it("the filename and the manifest's session_id agree", function()
    -- The binding that stops a seal being copied sideways: manifest-A.json
    -- claiming session B would be verified against B's pubkey but read as A's.
    roll()
    local names = rolling.filenames(SESSION_ID)
    local parsed = rolling.parse_filename(names.json)
    assert.is_table(parsed)

    local res = rolling.validate_session_manifest(decoded_manifest(), parsed.session_id)
    assert.is_true(res.ok, res.error and rolling.describe_error(res.error))
  end)

  it("covers exactly one session — its own", function()
    roll({ prev_session_id = OTHER_SESSION_ID })
    local m = decoded_manifest()
    assert.equals("1.2", m.format_version)
    assert.equals(1, #m.sessions)
    assert.equals(SESSION_ID, m.sessions[1].session_id)
    assert.equals(OTHER_SESSION_ID, m.sessions[1].prev_session_id)
  end)

  -- --- signing --------------------------------------------------------------

  it("is signed by THIS session's own key, and by no other", function()
    local res = roll()
    local pub = ed25519.to_hex(ed25519.public_key_of(PRIV))
    local other_pub = ed25519.to_hex(ed25519.public_key_of(OTHER_PRIV))

    assert.equals(res.canonical_json, read_all(res.manifest_path))
    assert.equals(res.signature_hex, read_all(res.sig_path))
    assert.is_true(bundle.verify_sig(res.canonical_json, res.signature_hex, pub))
    assert.is_false(bundle.verify_sig(res.canonical_json, res.signature_hex, other_pub))
  end)

  it("a seal signed with the wrong key does not verify against the session pubkey", function()
    local res = roll({ session_privkey = OTHER_PRIV })
    local pub = ed25519.to_hex(ed25519.public_key_of(PRIV))
    assert.is_false(bundle.verify_sig(res.canonical_json, res.signature_hex, pub))
  end)

  -- --- content --------------------------------------------------------------

  it("hashes the .slog and .slog.meta as they stand right now", function()
    roll()
    local m = decoded_manifest()
    assert.equals(sha256.hex('{"seq":0}'), m.sessions[1].slog_sha256)
    assert.equals(sha256.hex('{"session_id":"x"}'), m.sessions[1].meta_sha256)

    -- The log grows; the next roll commits to the longer prefix.
    write_file(provenance_dir .. "/session-abc.slog", '{"seq":0}\n{"seq":1}')
    roll()
    assert.equals(sha256.hex('{"seq":0}\n{"seq":1}'), decoded_manifest().sessions[1].slog_sha256)
  end)

  it("records reviewed files present/missing exactly as the classic seal does", function()
    roll()
    local files = decoded_manifest().submission_files
    assert.equals(2, #files)
    assert.equals("present.java", files[1].path)
    assert.equals("present", files[1].status)
    assert.equals(sha256.hex("class Present {}"), files[1].sha256)
    assert.equals("absent.java", files[2].path)
    assert.equals("missing", files[2].status)
    assert.equals(vim.NIL, files[2].sha256)
  end)

  it("keeps submission_files order stable across rolls", function()
    -- Churning the order would churn the canonical bytes for no reason.
    local a = roll().canonical_json
    local b = roll().canonical_json
    assert.equals(a, b)
  end)

  -- --- the `final` marker ---------------------------------------------------

  it("omits `final` on an ordinary roll", function()
    local res = roll()
    assert.is_nil(string.find(res.canonical_json, "final", 1, true))
    assert.is_nil(decoded_manifest()["final"])
    assert.is_false(rolling.is_final(decoded_manifest()))
  end)

  it("omits `final` when the caller passes false — never writes final:false", function()
    local res = roll({ final = false })
    assert.is_nil(string.find(res.canonical_json, "final", 1, true))
    assert.equals(roll().canonical_json, res.canonical_json)
  end)

  it("writes final:true on, and only on, the roll that asks for it", function()
    local res = roll({ final = true })
    assert.is_true(decoded_manifest()["final"])
    assert.is_true(rolling.is_final(decoded_manifest()))
    assert.is_not_nil(string.find(res.canonical_json, '"final":true', 1, true))

    -- And it is inside the SIGNED payload, so it cannot be added or stripped
    -- without the session key.
    local pub = ed25519.to_hex(ed25519.public_key_of(PRIV))
    assert.is_true(bundle.verify_sig(res.canonical_json, res.signature_hex, pub))
    local stripped = res.canonical_json:gsub('"final":true,', "", 1)
    assert.are_not.equal(res.canonical_json, stripped)
    assert.is_false(bundle.verify_sig(stripped, res.signature_hex, pub))
  end)

  -- --- atomicity ------------------------------------------------------------

  it("stages BOTH files before renaming EITHER (write-temp-then-rename)", function()
    -- A rolling manifest is rewritten repeatedly into a directory that gets
    -- committed. Writing in place would leave a corrupt signed artifact behind
    -- a crash; renaming the .json before the .sig is staged would widen the
    -- window in which a commit captures a mismatched pair.
    local uv = vim.uv or vim.loop
    local real_open, real_rename = uv.fs_open, uv.fs_rename
    local events = {}

    uv.fs_open = function(path, flags, mode)
      if path:match("%.tmp$") and flags == "w" then
        events[#events + 1] = { op = "stage", path = path }
      end
      return real_open(path, flags, mode)
    end
    uv.fs_rename = function(from, to)
      events[#events + 1] = { op = "rename", from = from, to = to }
      return real_rename(from, to)
    end

    local res
    local ok, err = pcall(function()
      res = roll()
    end)
    uv.fs_open, uv.fs_rename = real_open, real_rename
    assert.is_true(ok, tostring(err))
    assert.equals("written", res.kind)

    local stages, renames = {}, {}
    local first_rename_at
    for i, e in ipairs(events) do
      if e.op == "stage" then
        stages[#stages + 1] = e
        assert.is_nil(first_rename_at, "a temp was staged AFTER a rename had already been issued")
      else
        renames[#renames + 1] = e
        first_rename_at = first_rename_at or i
      end
    end

    assert.equals(2, #stages)
    assert.equals(2, #renames)
    for _, r in ipairs(renames) do
      assert.is_not_nil(r.from:match("%.tmp$"), "target must be reached by renaming a temp, not written in place")
    end
    assert.same({ res.manifest_path, res.sig_path }, { renames[1].to, renames[2].to })
  end)

  it("leaves no .tmp siblings behind", function()
    roll()
    roll({ final = true })
    assert.same({}, vim.fn.glob(provenance_dir .. "/*.tmp", true, true))
  end)

  -- --- degraded path --------------------------------------------------------

  it("returns an error value (never raises) when .provenance/ is gone", function()
    -- A `git checkout` can remove the directory mid-session.
    vim.fn.delete(provenance_dir, "rf")
    local res
    local ok = pcall(function()
      res = roll()
    end)
    assert.is_true(ok, "write_rolling_seal must never raise")
    assert.equals("error", res.kind)
    assert.is_string(res.message)
  end)

  it("does NOT recreate a .provenance/ that has been removed", function()
    -- Recreating it would leave a signed manifest sealing a log that is not
    -- there, and would resurrect a directory the student or git just deleted.
    vim.fn.delete(provenance_dir, "rf")
    roll()
    assert.is_false(exists(provenance_dir))
  end)

  it("returns an error value when the private key is unusable", function()
    local res
    local ok = pcall(function()
      res = roll({ session_privkey = "too-short" })
    end)
    assert.is_true(ok)
    assert.equals("error", res.kind)
  end)
end)
