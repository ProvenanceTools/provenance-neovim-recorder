--- Tests for registry.lua: the root -> session map replacing the single
--- state/controller pair (Plan: 2026-07-20-nested-manifest-discovery).
--- Mirrors init_controller_spec.lua's injected start_recording spy style so
--- this never starts a real recording session or touches the filesystem.
local registry_mod = require("provenance.recorder.registry")

local function make_start_recording_spy()
  local calls = {}
  local function start_recording(args)
    local fake_controller = { stop_calls = {} }
    function fake_controller.stop(reason)
      table.insert(fake_controller.stop_calls, reason)
    end
    table.insert(calls, { args = args, controller = fake_controller })
    return fake_controller
  end
  return start_recording, calls
end

describe("registry.new", function()
  it("fresh registry: is_active() is false, list() is empty", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    assert.is_false(reg.is_active())
    assert.same({}, reg.list())
  end)

  it("ensure_session: starts a session with workspace/provenance_dir/manifest derived from root", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    local manifest = { assignment_id = "hw3" }

    local controller, started = reg.ensure_session("/tmp/ws-a", manifest)

    assert.is_true(started)
    assert.is_not_nil(controller)
    assert.equals(1, #calls)
    assert.equals("/tmp/ws-a", calls[1].args.workspace)
    assert.equals("/tmp/ws-a/.provenance", calls[1].args.provenance_dir)
    assert.equals(manifest, calls[1].args.manifest)
    assert.is_true(reg.is_active())
    assert.is_true(reg.has_session("/tmp/ws-a"))
  end)

  it("ensure_session is idempotent: a second call for the SAME root does not start a second session", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    local manifest = { assignment_id = "hw3" }

    local c1, started1 = reg.ensure_session("/tmp/ws-a", manifest)
    local c2, started2 = reg.ensure_session("/tmp/ws-a", manifest)

    assert.equals(1, #calls)
    assert.is_true(started1)
    assert.is_false(started2)
    assert.equals(c1, c2)
  end)

  it("CONCURRENCY: two different roots each get their own session", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })

    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    assert.equals(2, #calls)
    assert.is_true(reg.has_session("/tmp/cats"))
    assert.is_true(reg.has_session("/tmp/hog"))
    assert.is_true(reg.is_active())

    local list = reg.list()
    assert.equals(2, #list)
    -- Sorted by root ascending.
    assert.equals("/tmp/cats", list[1].root)
    assert.equals("/tmp/hog", list[2].root)
  end)

  it("get(root) returns the stored entry; get() for an unknown root returns nil", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })

    local entry = reg.get("/tmp/cats")
    assert.equals("cats", entry.manifest.assignment_id)
    assert.equals("/tmp/cats/.provenance", entry.provenance_dir)

    assert.is_nil(reg.get("/tmp/nonexistent"))
  end)

  it("ensure_session propagates extra_opts to start_recording, extra_opts winning on conflicts", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })

    reg.ensure_session("/tmp/cats", { assignment_id = "cats" }, { clock = "injected-clock", provenance_dir = "/tmp/cats/.override" })

    assert.equals("injected-clock", calls[1].args.clock)
    assert.equals("/tmp/cats/.override", calls[1].args.provenance_dir)
  end)

  it("ensure_session on a start_recording failure does not register a half-open entry", function()
    local reg = registry_mod.new({
      start_recording = function()
        error("boom")
      end,
    })

    local controller, started, err = reg.ensure_session("/tmp/cats", { assignment_id = "cats" })

    assert.is_nil(controller)
    assert.is_false(started)
    assert.is_not_nil(err)
    assert.is_false(reg.has_session("/tmp/cats"))
    assert.is_false(reg.is_active())
  end)

  it("stop_all: stops every session exactly once and clears the registry", function()
    local start_recording, calls = make_start_recording_spy()
    local reg = registry_mod.new({ start_recording = start_recording })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    reg.stop_all("deactivate")

    assert.equals(1, #calls[1].controller.stop_calls)
    assert.equals("deactivate", calls[1].controller.stop_calls[1])
    assert.equals(1, #calls[2].controller.stop_calls)
    assert.is_false(reg.is_active())
    assert.same({}, reg.list())
  end)

  it("stop_all is safe to call with zero active sessions", function()
    local start_recording = select(1, make_start_recording_spy())
    local reg = registry_mod.new({ start_recording = start_recording })
    assert.has_no.errors(function()
      reg.stop_all("deactivate")
    end)
  end)

  it("stop_all does not stop the SAME controller twice if a controller.stop() call throws", function()
    local reg = registry_mod.new({
      start_recording = function()
        return { stop = function() error("stop failed") end }
      end,
    })
    reg.ensure_session("/tmp/cats", { assignment_id = "cats" })
    reg.ensure_session("/tmp/hog", { assignment_id = "hog" })

    -- A throwing stop() for one entry must not prevent the OTHER entry
    -- from being stopped and cleared too.
    assert.has_no.errors(function()
      reg.stop_all("deactivate")
    end)
    assert.is_false(reg.is_active())
  end)
end)

--- The verified-root cache. Activation resolution runs on every BufEnter /
--- BufReadPost / BufNewFile, and each uncached resolve pays a ~12 ms pure-Lua
--- ed25519 verification on the main loop. These tests pin BOTH halves of the
--- fix: that a byte-identical re-read skips verification, and that ANY change
--- to the manifest's bytes forces a fresh one.
describe("registry.load_and_verify (verified-root cache)", function()
  local activation = require("provenance.recorder.activation")

  local function this_file_dir()
    local source = debug.getinfo(1, "S").source
    local path = source:match("^@(.*)$") or source
    return vim.fn.fnamemodify(path, ":h")
  end

  local fx = vim.json.decode(
    table.concat(vim.fn.readfile(this_file_dir() .. "/../conformance/fixtures/manifest.json"), "\n")
  )
  -- A real 2.0 manifest whose course_cert chains to the embedded DEV ROOT key.
  local dev_v2_text = table.concat(vim.fn.readfile(this_file_dir() .. "/fixtures/dev-manifest-v2.json"), "\n")

  local real_evaluate = activation.evaluate
  local evaluate_calls
  local tempdirs

  before_each(function()
    evaluate_calls = 0
    tempdirs = {}
    activation.evaluate = function(text, pubkey_hex)
      evaluate_calls = evaluate_calls + 1
      return real_evaluate(text, pubkey_hex)
    end
  end)

  after_each(function()
    activation.evaluate = real_evaluate
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
  end)

  local function new_reg()
    return registry_mod.new({ start_recording = select(1, make_start_recording_spy()) })
  end

  local function new_workspace(manifest)
    local dir = vim.fn.tempname()
    vim.fn.mkdir(dir, "p")
    table.insert(tempdirs, dir)
    vim.fn.writefile({ vim.json.encode(manifest or fx.manifest) }, dir .. "/.provenance-manifest")
    return dir
  end

  it("verifies on first sight of a root and returns the same verdict as activation.load_and_verify", function()
    local reg = new_reg()
    local dir = new_workspace()

    local res = reg.load_and_verify(dir, fx.course_pubkey_hex)

    assert.equals("active", res.status)
    assert.equals("hw3", res.manifest.assignment_id)
    assert.equals(1, evaluate_calls)
  end)

  it("serves a byte-identical re-read from the cache without re-verifying", function()
    local reg = new_reg()
    local dir = new_workspace()

    local first = reg.load_and_verify(dir, fx.course_pubkey_hex)
    for _ = 1, 5 do
      local again = reg.load_and_verify(dir, fx.course_pubkey_hex)
      assert.equals("active", again.status)
      assert.equals(first, again)
    end

    assert.equals(1, evaluate_calls)
  end)

  it("caches a NEGATIVE verdict too (a failing manifest must not re-verify on every buffer switch)", function()
    local reg = new_reg()
    local tampered = vim.json.decode(vim.json.encode(fx.manifest))
    tampered.files_under_review = { "src/tampered.py" }
    local dir = new_workspace(tampered)

    assert.equals("signature_invalid", reg.load_and_verify(dir, fx.course_pubkey_hex).reason)
    assert.equals("signature_invalid", reg.load_and_verify(dir, fx.course_pubkey_hex).reason)
    assert.equals(1, evaluate_calls)
  end)

  it("re-verifies after the manifest file changes, and the verdict follows the new bytes", function()
    local reg = new_reg()
    local dir = new_workspace()
    assert.equals("active", reg.load_and_verify(dir, fx.course_pubkey_hex).status)

    local tampered = vim.json.decode(vim.json.encode(fx.manifest))
    tampered.assignment_id = "hw4"
    vim.fn.writefile({ vim.json.encode(tampered) }, dir .. "/.provenance-manifest")

    local after = reg.load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals("inactive", after.status)
    assert.equals("signature_invalid", after.reason)
    assert.equals(2, evaluate_calls)
  end)

  it("busts the cache on a same-SIZE, same-MTIME manifest swap (why the key is a content digest)", function()
    local reg = new_reg()
    local dir = new_workspace()
    local path = dir .. "/.provenance-manifest"
    local uv = vim.uv or vim.loop

    assert.equals("active", reg.load_and_verify(dir, fx.course_pubkey_hex).status)
    local before = uv.fs_stat(path)

    -- Same byte length, and mtime/atime restored afterwards: an mtime+size
    -- cache key would still report a hit here and keep serving "active" for a
    -- manifest that no longer verifies. The cache would BE the attack.
    local forged = vim.json.decode(vim.json.encode(fx.manifest))
    forged.semester = string.rep("x", #forged.semester)
    local forged_text = vim.json.encode(forged)
    assert.equals(#vim.json.encode(fx.manifest), #forged_text, "forgery must be the same length")
    vim.fn.writefile({ forged_text }, path)
    uv.fs_utime(path, before.atime.sec, before.mtime.sec)

    local after = uv.fs_stat(path)
    assert.equals(before.size, after.size)
    assert.equals(before.mtime.sec, after.mtime.sec)

    local res = reg.load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals("inactive", res.status)
    assert.equals("signature_invalid", res.reason)
    assert.equals(2, evaluate_calls)
  end)

  it("keys the cache on the public key too: a different key re-verifies", function()
    local reg = new_reg()
    local dir = new_workspace()

    assert.equals("active", reg.load_and_verify(dir, fx.course_pubkey_hex).status)
    local other = reg.load_and_verify(dir, string.rep("ab", 32))
    assert.equals("signature_invalid", other.reason)
    assert.equals(2, evaluate_calls)

    -- and both verdicts are still correct afterwards (last write wins in the
    -- cache, so the original key simply re-verifies)
    assert.equals("active", reg.load_and_verify(dir, fx.course_pubkey_hex).status)
    assert.equals(3, evaluate_calls)
  end)

  it("caches per root: two roots are each verified once", function()
    local reg = new_reg()
    local a, b = new_workspace(), new_workspace()

    reg.load_and_verify(a, fx.course_pubkey_hex)
    reg.load_and_verify(b, fx.course_pubkey_hex)
    reg.load_and_verify(a, fx.course_pubkey_hex)
    reg.load_and_verify(b, fx.course_pubkey_hex)

    assert.equals(2, evaluate_calls)
  end)

  it("caches nothing when there is no manifest file (no bytes to key on, nothing expensive ran)", function()
    local reg = new_reg()
    local dir = vim.fn.tempname()
    vim.fn.mkdir(dir, "p")
    table.insert(tempdirs, dir)

    local res = reg.load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals("inactive", res.status)
    assert.equals("no_manifest_file", res.reason)
    assert.equals(0, evaluate_calls)
  end)

  it("two registries do not share a cache", function()
    local dir = new_workspace()
    new_reg().load_and_verify(dir, fx.course_pubkey_hex)
    new_reg().load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals(2, evaluate_calls)
  end)

  --- Since Manifest 2.0 there are TWO embedded trust anchors and the one that
  --- applies is chosen from the manifest's own format_version. A cached verdict
  --- must therefore never survive a manifest switching versions under the same
  --- root -- otherwise a 2.0 read could be answered by a verdict computed under
  --- the legacy course key, or vice versa. The content digest is what closes
  --- this: different bytes, different version, different digest, guaranteed miss.
  it("a manifest that switches format version between reads never hits the other anchor's verdict", function()
    local reg = new_reg()
    local dir = new_workspace() -- 1.x, verified under the legacy path

    local first = reg.load_and_verify(dir)
    assert.equals(1, evaluate_calls)

    -- Same root, same file, now a 2.0 manifest that chains to the embedded root
    -- key. It must be re-evaluated, and it must come back ACTIVE -- which it can
    -- only do via the 2.0 anchor.
    vim.fn.writefile(vim.split(dev_v2_text, "\n"), dir .. "/.provenance-manifest")
    local second = reg.load_and_verify(dir)
    assert.equals(2, evaluate_calls, "the 2.0 read must not be served from the 1.x verdict")
    assert.is_not.equals(first, second)
    assert.equals("active", second.status)
    assert.equals("2.0", second.manifest.format_version)

    -- and back again: the 1.x bytes must not be answered by the 2.0 verdict.
    vim.fn.writefile({ vim.json.encode(fx.manifest) }, dir .. "/.provenance-manifest")
    local third = reg.load_and_verify(dir)
    assert.equals(3, evaluate_calls)
    assert.is_not.equals(second, third)
    assert.equals("inactive", third.status)
  end)

  it("each format version still caches normally once it has been seen", function()
    local reg = new_reg()
    local dir = vim.fn.tempname()
    vim.fn.mkdir(dir, "p")
    table.insert(tempdirs, dir)
    vim.fn.writefile(vim.split(dev_v2_text, "\n"), dir .. "/.provenance-manifest")

    local first = reg.load_and_verify(dir)
    assert.equals("active", first.status)
    for _ = 1, 3 do
      assert.equals(first, reg.load_and_verify(dir))
    end
    assert.equals(1, evaluate_calls, "a 2.0 chain walk is ~23 ms; it must be cached too")
  end)

  it("the cache keys on the pubkey OVERRIDE, so nil and an explicit key are distinct entries", function()
    local reg = new_reg()
    local dir = new_workspace()

    -- nil override -> the 1.x anchor (the legacy course key), which did not sign
    -- this fixture; explicit override -> the key that did.
    assert.equals("inactive", reg.load_and_verify(dir).status)
    assert.equals("active", reg.load_and_verify(dir, fx.course_pubkey_hex).status)
    assert.equals(2, evaluate_calls)
    -- One entry per root, last write wins: the explicit-override verdict is the
    -- one now cached, and it is still correct on a repeat. In production there
    -- is exactly one override (none), so this only ever costs hit rate, never
    -- correctness -- the key comparison is what guarantees the latter.
    assert.equals("active", reg.load_and_verify(dir, fx.course_pubkey_hex).status)
    assert.equals(2, evaluate_calls)
  end)

  it("clear_verification_cache forces the next resolve to re-verify", function()
    local reg = new_reg()
    local dir = new_workspace()

    reg.load_and_verify(dir, fx.course_pubkey_hex)
    reg.load_and_verify(dir, fx.course_pubkey_hex)
    assert.equals(1, evaluate_calls)

    reg.clear_verification_cache()
    assert.equals("active", reg.load_and_verify(dir, fx.course_pubkey_hex).status)
    assert.equals(2, evaluate_calls)
  end)
end)
