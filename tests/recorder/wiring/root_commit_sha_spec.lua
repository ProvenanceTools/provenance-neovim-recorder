--- The repository discriminator, write side (decision D12, collaboration spec
--- S14(b)).
---
--- The reader is correct whatever the writer picks — the value is opaque and
--- compared only for equality — so every test here is really one question:
--- would provcode, provjet and provnvim, on the same repository, derive the
--- SAME value? A discriminator two partners disagree about correlates nothing,
--- which is the whole reason the derivation is specified at all.
local root_commit_sha = require("provenance.recorder.wiring.root_commit_sha")
local git_event = require("provenance.core.git_event")

--- A `run_git` seam that answers a fixed table of arg-lists, records what it
--- was asked, and defaults to a non-zero exit for anything unexpected.
local function seam(answers)
  local calls = {}
  local run = function(args)
    local key = table.concat(args, " ")
    calls[#calls + 1] = key
    local a = answers[key]
    if a == nil then
      return { ok = false, out = "" }
    end
    if type(a) == "function" then
      return a()
    end
    return a
  end
  return run, calls
end

local NOT_SHALLOW = { ["rev-parse --is-shallow-repository"] = { ok = true, out = "false\n" } }
local ROOTS = "rev-list --max-parents=0 --first-parent HEAD"

local A40 = ("a"):rep(40)
local B40 = ("b"):rep(40)
local C64 = ("c"):rep(64)

describe("root_commit_sha.derive", function()
  it("returns the root of HEAD's FIRST-PARENT lineage", function()
    local run, calls = seam(vim.tbl_extend("force", NOT_SHALLOW, {
      [ROOTS] = { ok = true, out = A40 .. "\n" },
    }))
    assert.equals(A40, root_commit_sha.derive(run))
    -- The exact argv matters: `--first-parent` is what keeps two partners
    -- agreeing when an imported history is merged in, and dropping it is a
    -- silent divergence rather than an error.
    assert.same({ "rev-parse --is-shallow-repository", ROOTS }, calls)
  end)

  it("accepts a sha-256 repository's 64-hex root", function()
    local run = seam(vim.tbl_extend("force", NOT_SHALLOW, {
      [ROOTS] = { ok = true, out = C64 .. "\n" },
    }))
    assert.equals(C64, root_commit_sha.derive(run))
  end)

  it("takes the LEXICOGRAPHICALLY SMALLEST when there is more than one root", function()
    -- An orphan branch, or a squashed import merged in. ORDINARY, never a
    -- finding — and the tie-break has to be deterministic or two partners with
    -- identical history disagree. Deliberately fed in a non-sorted order, and
    -- not in git's own order either.
    local run = seam(vim.tbl_extend("force", NOT_SHALLOW, {
      [ROOTS] = { ok = true, out = B40 .. "\n" .. A40 .. "\n" .. ("0"):rep(40) .. "\n" },
    }))
    assert.equals(("0"):rep(40), root_commit_sha.derive(run))
  end)

  it("is stable across permutations of the same root set", function()
    local roots = { A40, B40, ("9"):rep(40) }
    local first
    for _, order in ipairs({ { 1, 2, 3 }, { 3, 2, 1 }, { 2, 3, 1 } }) do
      local lines = {}
      for _, i in ipairs(order) do
        lines[#lines + 1] = roots[i]
      end
      local run = seam(vim.tbl_extend("force", NOT_SHALLOW, {
        [ROOTS] = { ok = true, out = table.concat(lines, "\n") },
      }))
      local got = root_commit_sha.derive(run)
      first = first or got
      assert.equals(first, got)
    end
    assert.equals(("9"):rep(40), first)
  end)

  describe("OMIT — absence is legal, permanent and blameless", function()
    it("omits on a SHALLOW clone, and never even asks for the roots", function()
      -- A shallow clone's boundary commit has no parents and IS printed by
      -- `rev-list --max-parents=0`, so emitting it would publish a value a full
      -- clone of the same repository disagrees with: a silent failure to
      -- correlate, dressed as a successful one. The second command must not run
      -- at all — asking and then discarding would be one subprocess of wasted
      -- work and one more chance to get the discard wrong.
      local run, calls = seam({
        ["rev-parse --is-shallow-repository"] = { ok = true, out = "true\n" },
        [ROOTS] = { ok = true, out = A40 .. "\n" },
      })
      assert.is_nil(root_commit_sha.derive(run))
      assert.same({ "rev-parse --is-shallow-repository" }, calls)
    end)

    it("omits when `--is-shallow-repository` is unknown (git < 2.15 exits non-zero)", function()
      -- Named explicitly because the corrected contract calls it out: an older
      -- git errors on the flag, which lands in "omit on any failure". That is
      -- the mechanism, not a special case — the answer for "I cannot tell
      -- whether this clone is shallow" is the answer for "it is".
      local run, calls = seam({
        ["rev-parse --is-shallow-repository"] = {
          ok = false,
          out = "error: unknown option `is-shallow-repository'",
        },
        [ROOTS] = { ok = true, out = A40 .. "\n" },
      })
      assert.is_nil(root_commit_sha.derive(run))
      assert.same({ "rev-parse --is-shallow-repository" }, calls)
    end)

    it("omits on anything that is not a definite `false`", function()
      for _, answer in ipairs({ "", "TRUE", "yes", "false false", "unknown" }) do
        local run = seam(vim.tbl_extend("force", {
          ["rev-parse --is-shallow-repository"] = { ok = true, out = answer },
        }, { [ROOTS] = { ok = true, out = A40 } }))
        assert.is_nil(root_commit_sha.derive(run), "answer: " .. answer)
      end
    end)

    it("omits when rev-list fails, or an empty repository yields nothing", function()
      for _, answer in ipairs({
        { ok = false, out = "fatal: ambiguous argument 'HEAD'" },
        { ok = true, out = "" },
        { ok = true, out = "\n\n  \n" },
      }) do
        local run = seam(vim.tbl_extend("force", NOT_SHALLOW, { [ROOTS] = answer }))
        assert.is_nil(root_commit_sha.derive(run))
      end
    end)

    it("omits when git is missing entirely (the seam throws)", function()
      -- `git_wiring`'s default seam degrades a missing binary to {ok=false},
      -- but an injected one might throw. Never raises: every failure is an
      -- omission, because guessing is worse than silence.
      assert.is_nil(root_commit_sha.derive(function()
        error("no git binary")
      end))
      assert.is_nil(root_commit_sha.derive(function()
        return nil
      end))
      assert.is_nil(root_commit_sha.derive(nil))
      assert.is_nil(root_commit_sha.derive(42))
    end)
  end)

  describe("S14(b) — a path or a remote URL can never become the value", function()
    it("rejects every non-object-name line git could print", function()
      -- The shape check is the ONE place a nonconforming value is stopped
      -- before it reaches a staff-facing UI, and running it on the WRITE side
      -- means it is never written down at all.
      for _, line in ipairs({
        "/Users/student/cs61b/proj2",
        "C:\\Users\\student\\proj2",
        "git@github.com:acme/cs61b-proj2.git",
        "https://github.com/acme/cs61b-proj2",
        ("A"):rep(40), -- uppercase: rejected, never case-folded
        ("a"):rep(39),
        ("a"):rep(41),
        ("a"):rep(63),
        ("a"):rep(65),
        "9999999", -- an abbreviation is not the same value as the full sha
        "fatal: not a git repository",
        "warning: refname 'HEAD' is ambiguous.",
      }) do
        local run = seam(vim.tbl_extend("force", NOT_SHALLOW, {
          [ROOTS] = { ok = true, out = line .. "\n" },
        }))
        assert.is_nil(root_commit_sha.derive(run), "must reject: " .. line)
      end
    end)

    it("validates through log-core's own reader, not a private regex", function()
      -- The property, stated as a property: for EVERY line git could print,
      -- derive() returns it only if log-core's reader would call it
      -- `recorded`. A writer that shape-checks with its own copy of the rule
      -- can emit a value its reader rejects; this one cannot.
      for _, line in ipairs({
        A40,
        C64,
        ("A"):rep(40),
        ("a"):rep(41),
        "9999999",
        "",
        "/tmp/repo",
      }) do
        local run = seam(vim.tbl_extend("force", NOT_SHALLOW, {
          [ROOTS] = { ok = true, out = line .. "\n" },
        }))
        local derived = root_commit_sha.derive(run)
        assert.equals(
          git_event.is_usable_discriminator(line),
          derived ~= nil,
          "disagreed with the reader on: " .. line
        )
        if derived ~= nil then
          assert.equals(line, derived)
        end
      end
    end)

    it("a usable root survives a line of git chatter beside it", function()
      -- Chatter is dropped, the object name is kept, and the answer is still
      -- the smallest usable one — not "the first line", which is how a path
      -- printed above the roots would win.
      local run = seam(vim.tbl_extend("force", NOT_SHALLOW, {
        [ROOTS] = {
          ok = true,
          out = "warning: something\n" .. B40 .. "\n/Users/student/x\n" .. A40 .. "\n",
        },
      }))
      assert.equals(A40, root_commit_sha.derive(run))
    end)
  end)

  it("makes no network call and reads no author identity", function()
    -- PRD NG2 plus the CPHS constraint (2026-06-19796). Both commands are local
    -- object-database reads, and neither can surface a name, an email, a date
    -- or a message. Asserted against the argv actually issued, so a future
    -- `--format=%an` is a failing test rather than a review catch.
    local run, calls = seam(vim.tbl_extend("force", NOT_SHALLOW, {
      [ROOTS] = { ok = true, out = A40 },
    }))
    root_commit_sha.derive(run)
    for _, argv in ipairs(calls) do
      for _, forbidden in ipairs({ "fetch", "remote", "ls-remote", "pull", "--format", "%a", "log" }) do
        assert.is_nil(argv:find(forbidden, 1, true), argv .. " must not contain " .. forbidden)
      end
    end
  end)
end)
