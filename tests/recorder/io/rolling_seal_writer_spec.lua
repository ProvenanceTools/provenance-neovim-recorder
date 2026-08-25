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

--- This spec file's own repo root, resolved from `debug.getinfo` (same
--- technique as `workspace_file_read_spec.lua`, in this same directory)
--- rather than `getcwd()`, so it does not depend on the Makefile's
--- invocation directory. Walks up from
--- `tests/recorder/io/rolling_seal_writer_spec.lua` to the repo root: strip
--- the filename, then `io` -> `recorder` -> `tests` -> root.
local function resolve_repo_root()
  local info = debug.getinfo(1, "S")
  local source = info.source
  assert(type(source) == "string" and source:sub(1, 1) == "@", "could not resolve spec file source path")
  local dir = source:sub(2)
  for _ = 1, 4 do
    dir = dir:match("^(.*)/[^/]+$")
    assert(dir ~= nil, "could not walk up to repo root from spec file path")
  end
  return dir
end

local REPO_ROOT = resolve_repo_root()

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
      scope = { track = { "present.java", "absent.java" } },
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

  -- --- unreadable vs missing: never mint a false "missing" -----------------
  --
  -- `read_file_bytes` used to collapse every read failure -- a directory, a
  -- permission error, a FIFO, any other errno -- to a bare nil, and
  -- `read_submission_file` turned every one of those into
  -- `status = "missing"`: an AFFIRMATIVE claim about a student ("this file
  -- was named and is not there") rendered into academic-integrity
  -- proceedings. Only ENOENT actually means that. This block proves the
  -- fix, mirroring the equivalent block in
  -- tests/recorder/commands/seal_spec.lua for the classic seal.

  local function submission_files_by_path()
    local by_path = {}
    for _, f in ipairs(decoded_manifest().submission_files) do
      by_path[f.path] = f
    end
    return by_path
  end

  it("drops a scope entry naming a DIRECTORY, never missing", function()
    -- fs_open SUCCEEDS on a directory on macOS, so this is a real trap.
    vim.fn.mkdir(workspace .. "/adir", "p")

    local res = roll({ scope = { track = { "present.java", "adir" } } })
    assert.equals("written", res.kind)

    local files, by_path = decoded_manifest().submission_files, submission_files_by_path()
    assert.equals(1, #files, "the directory entry must be dropped, not recorded at all")
    assert.equals("present", by_path["present.java"].status)
    assert.is_nil(by_path["adir"])
  end)

  it("drops a chmod-000 scope entry, never missing", function()
    local uv = vim.uv or vim.loop
    local secret = workspace .. "/secret.java"
    write_file(secret, "class Secret {}")
    uv.fs_chmod(secret, tonumber("000", 8))

    -- Verify the denial actually took effect before asserting; a uid that
    -- defeats permission bits (root) makes this pending rather than false.
    local fd = uv.fs_open(secret, "r", 438)
    if fd ~= nil then
      uv.fs_close(fd)
      uv.fs_chmod(secret, tonumber("644", 8))
      pending("running with elevated privileges that defeat permission bits")
      return
    end

    local res = roll({ scope = { track = { "present.java", "secret.java" } } })
    uv.fs_chmod(secret, tonumber("644", 8))
    assert.equals("written", res.kind)

    local files, by_path = decoded_manifest().submission_files, submission_files_by_path()
    assert.equals(1, #files)
    assert.equals("present", by_path["present.java"].status)
    assert.is_nil(by_path["secret.java"])
  end)

  it("still marks a genuinely absent entry as missing, distinct from an unreadable one", function()
    -- The regression a careless fix causes: this legitimate case must
    -- survive untouched even when an unreadable entry is present in the
    -- same roll. (`absent.java` is already part of the default `roll()`
    -- fixture -- this asserts it explicitly alongside a real unreadable
    -- entry rather than relying on the "records ... present/missing" test
    -- above.)
    vim.fn.mkdir(workspace .. "/adir", "p")

    local res = roll({ scope = { track = { "adir", "absent.java" } } })
    assert.equals("written", res.kind)

    local files, by_path = decoded_manifest().submission_files, submission_files_by_path()
    assert.equals(1, #files, "only the genuinely absent file is recorded")
    assert.equals("missing", by_path["absent.java"].status)
    assert.equals(vim.NIL, by_path["absent.java"].sha256)
    assert.is_nil(by_path["adir"])
  end)

  it("follows an ordinary in-workspace symlink to a real file, and reports it present", function()
    -- The case a careless fs_lstat swap would break: an in-workspace symlink
    -- is a file the student really did submit.
    local uv = vim.uv or vim.loop
    local ok = pcall(function()
      assert(uv.fs_symlink(workspace .. "/present.java", workspace .. "/link.java"))
    end)
    if not ok then
      pending("symlink creation not available on this machine")
      return
    end

    local res = roll({ scope = { track = { "link.java" } } })
    assert.equals("written", res.kind)

    local files, by_path = decoded_manifest().submission_files, submission_files_by_path()
    assert.equals(1, #files)
    assert.equals("present", by_path["link.java"].status)
    assert.equals(sha256.hex("class Present {}"), by_path["link.java"].sha256)
  end)

  it("does not hang on a FIFO tracked file, and drops it without emitting missing", function()
    -- Reading a FIFO with no writer BLOCKS THE ENTIRE NEOVIM PROCESS FOREVER
    -- (verified empirically, not theoretical), with no timeout anywhere in
    -- this call stack. `write_rolling_seal` runs on EVERY CHECKPOINT (no
    -- explicit seal command needed to trigger it), so the risky call must
    -- run in a CHILD `nvim -l` process under a wall-clock jobwait timeout,
    -- or a regression wedges the whole test run instead of failing one
    -- test. Same technique as workspace_file_read_spec.lua's FIFO test.
    if vim.fn.executable("mkfifo") == 0 then
      pending("mkfifo not available on this machine")
      return
    end

    local fifo = workspace .. "/pipe.java"
    vim.fn.system({ "mkfifo", fifo })
    if vim.v.shell_error ~= 0 then
      pending("mkfifo failed on this machine")
      return
    end

    local out_file = workspace .. "/result.txt"
    local child_script = workspace .. "/child.lua"
    local script = string.format(
      [[
package.path = %q .. "/lua/?.lua;" .. %q .. "/lua/?/init.lua;" .. package.path
local w = require("provenance.recorder.io.rolling_seal_writer")
local res = w.write_rolling_seal({
  provenance_dir = %q,
  session_id = %q,
  prev_session_id = nil,
  slog_path = %q,
  workspace = %q,
  assignment_id = "proj2",
  semester = "fa26",
  scope = { track = { "present.java", "pipe.java" } },
  session_privkey = %q,
  extension_hash = %q,
})
local f = assert(io.open(%q, "w"))
f:write(res.kind)
f:close()
]],
      REPO_ROOT,
      REPO_ROOT,
      provenance_dir,
      SESSION_ID,
      provenance_dir .. "/session-abc.slog",
      workspace,
      PRIV,
      EXT_HASH,
      out_file
    )
    write_file(child_script, script)

    local job = vim.fn.jobstart({ "nvim", "-l", child_script })
    assert.is_true(job > 0, "failed to start child nvim -l process")

    local waited = vim.fn.jobwait({ job }, 5000)
    if waited[1] == -1 then
      pcall(vim.fn.jobstop, job)
      assert.is_true(false, "write_rolling_seal HUNG on a FIFO: did not return within 5s")
      return
    end

    assert.is_true(vim.fn.filereadable(out_file) == 1, "child process produced no result file")
    local lines = vim.fn.readfile(out_file)
    assert.equals("written", lines[1])

    local files, by_path = decoded_manifest().submission_files, submission_files_by_path()
    assert.equals(1, #files)
    assert.equals("present", by_path["present.java"].status)
    assert.is_nil(by_path["pipe.java"])
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

--- Invariant test 9 (Task F): the ROLLING seal uses the SAME two-loop
--- path-scope collection as the classic seal (via the same shared
--- `workspace_walk` / `workspace_file_read` modules), so the two seals of one
--- session cannot disagree about a file's status. Only EXACT track entries
--- may mint `missing`; `scope_capped` is omitted unless exactly `true`.
describe("rolling_seal_writer path scope (Task F)", function()
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
      scope = { track = {}, ignore = {}, attachments = {} },
      session_privkey = PRIV,
      extension_hash = EXT_HASH,
    }
    for k, v in pairs(overrides or {}) do
      opts[k] = v
    end
    return writer.write_rolling_seal(opts)
  end

  it("collects rule-matched files via the shared walk, with role; an attachment is hashed too", function()
    vim.fn.mkdir(workspace .. "/src", "p")
    write_file(workspace .. "/src/Main.java", "class Main {}")
    write_file(workspace .. "/README.md", "notes")
    vim.fn.mkdir(workspace .. "/logs", "p")
    write_file(workspace .. "/logs/run.log", "output")

    local res = roll({ scope = { track = { "src/" }, ignore = {}, attachments = { "logs/" } } })
    assert.equals("written", res.kind)

    local files = vim.json.decode(read_all(res.manifest_path)).submission_files
    local by_path = {}
    for _, f in ipairs(files) do
      by_path[f.path] = f
    end
    assert.equals("reviewed", by_path["src/Main.java"].role)
    assert.equals(sha256.hex("class Main {}"), by_path["src/Main.java"].sha256)
    assert.equals("attachment", by_path["logs/run.log"].role)
    assert.is_nil(by_path["README.md"], "unscoped files are not collected at all")
  end)

  it("only an EXACT track entry mints missing; a rule entry says nothing about a file never written", function()
    local res = roll({ scope = { track = { "*.java", "Required.java" }, ignore = {}, attachments = {} } })
    assert.equals("written", res.kind)

    local files = vim.json.decode(read_all(res.manifest_path)).submission_files
    local missing = {}
    for _, f in ipairs(files) do
      if f.status == "missing" then
        missing[#missing + 1] = f.path
      end
    end
    assert.same({ "Required.java" }, missing)
  end)

  it("omits scope_capped when false, and includes it -- inside the signed bytes -- when true", function()
    local res_false = roll({ scope_capped = false })
    assert.equals("written", res_false.kind)
    assert.is_nil(res_false.canonical_json:find('"scope_capped"', 1, true))
    assert.is_nil(vim.json.decode(read_all(res_false.manifest_path)).scope_capped)

    local res_true = roll({ scope_capped = true })
    assert.equals("written", res_true.kind)
    assert.is_truthy(res_true.canonical_json:find('"scope_capped":true', 1, true))
    assert.is_true(vim.json.decode(read_all(res_true.manifest_path)).scope_capped)
  end)
end)
