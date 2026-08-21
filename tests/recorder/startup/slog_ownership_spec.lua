--- slog_ownership — the gate that stands between startup recovery and a
--- partner's evidence (decision-log bug 2).
---
--- The module answers one question — is this `.slog` mine? — and the cost of
--- each wrong answer is asymmetric, so the spec is organised around that:
--- calling a partner's log ours renames it out of their submission; calling
--- our own log foreign loses a back-pointer. Everything below is a variant of
--- "which way does this case fall, and why is that the cheaper mistake".
local slog_ownership = require("provenance.recorder.startup.slog_ownership")

local ALICE = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
local BOB = "9a7b1c2d-3e4f-4a5b-8c9d-0e1f2a3b4c5d"

--- One NDJSON line good enough for a first-line read. The hash fields are not
--- consulted by this module (it never validates a chain — that is
--- chain_recovery's job on a file already proven eligible), so a plausible
--- session.start envelope is enough.
local function session_start_line(opts)
  opts = opts or {}
  local data = { session_id = opts.session_id or "sid" }
  if opts.student_ref ~= nil then
    data.identity = {
      enrollment = { student_ref = opts.student_ref, course_id = "berkeley-cs61b" },
    }
  end
  return vim.json.encode({
    seq = 0,
    t = 0,
    wall = "2026-01-01T00:00:00.000Z",
    kind = opts.kind or "session.start",
    data = data,
    prev_hash = ("00"):rep(32),
    hash = ("11"):rep(32),
  }) .. "\n"
end

describe("slog_ownership.student_ref_of_slog_text", function()
  it("reads student_ref out of the first line's session.start identity", function()
    assert.equals(ALICE, slog_ownership.student_ref_of_slog_text(session_start_line({ student_ref = ALICE })))
  end)

  it("only ever reads the FIRST line — startup cost must not scale with a partner's log", function()
    local text = session_start_line({ student_ref = ALICE })
      .. session_start_line({ student_ref = BOB, kind = "doc.change" })
    assert.equals(ALICE, slog_ownership.student_ref_of_slog_text(text))
  end)

  it("is nil for a 1.x log with no identity block at all", function()
    assert.is_nil(slog_ownership.student_ref_of_slog_text(session_start_line()))
  end)

  it("is nil when the first entry is not a session.start", function()
    local text = session_start_line({ student_ref = ALICE, kind = "doc.change" })
    assert.is_nil(slog_ownership.student_ref_of_slog_text(text))
  end)

  it("is nil, never a throw, for garbage / empty / truncated / nil text", function()
    assert.is_nil(slog_ownership.student_ref_of_slog_text("{not json at all"))
    assert.is_nil(slog_ownership.student_ref_of_slog_text(""))
    assert.is_nil(slog_ownership.student_ref_of_slog_text("   \n"))
    assert.is_nil(slog_ownership.student_ref_of_slog_text('{"kind":"session.start","data":{"iden'))
    assert.is_nil(slog_ownership.student_ref_of_slog_text(nil))
    assert.is_nil(slog_ownership.student_ref_of_slog_text(vim.json.encode({ kind = "session.start" }) .. "\n"))
  end)

  it("is nil for a conflict-markered log — the case that got a partner's file renamed", function()
    local text = "<<<<<<< HEAD\n" .. session_start_line({ student_ref = ALICE })
    assert.is_nil(slog_ownership.student_ref_of_slog_text(text))
  end)

  it("is nil when identity/enrollment are present but the wrong shape", function()
    local weird = vim.json.encode({
      kind = "session.start",
      data = { identity = { enrollment = { student_ref = 42 } } },
    }) .. "\n"
    assert.is_nil(slog_ownership.student_ref_of_slog_text(weird))
    local scalar = vim.json.encode({ kind = "session.start", data = { identity = "nope" } }) .. "\n"
    assert.is_nil(slog_ownership.student_ref_of_slog_text(scalar))
    local empty = vim.json.encode({
      kind = "session.start",
      data = { identity = { enrollment = { student_ref = "" } } },
    }) .. "\n"
    assert.is_nil(slog_ownership.student_ref_of_slog_text(empty))
  end)
end)

describe("slog_ownership.classify", function()
  it("own: both refs present and equal", function()
    assert.equals("own", slog_ownership.classify(ALICE, ALICE))
  end)

  it("foreign: both present and different", function()
    assert.equals("foreign", slog_ownership.classify(ALICE, BOB))
  end)

  it("foreign (asymmetric): we have no ref and the candidate has one", function()
    -- We cannot claim to be a contributor we cannot name. Misfiling our own
    -- pre-enrollment log as foreign loses a link; misfiling a partner's log as
    -- ours destroys it.
    assert.equals("foreign", slog_ownership.classify(nil, BOB))
  end)

  it("unattributed: the candidate names nobody, whoever we are", function()
    assert.equals("unattributed", slog_ownership.classify(nil, nil))
    assert.equals("unattributed", slog_ownership.classify(ALICE, nil))
  end)
end)

describe("slog_ownership.is_eligible", function()
  it("own is always eligible", function()
    assert.is_true(slog_ownership.is_eligible("own", ALICE))
  end)

  it("foreign is NEVER eligible, for any recorder", function()
    assert.is_false(slog_ownership.is_eligible("foreign", ALICE))
    assert.is_false(slog_ownership.is_eligible("foreign", nil))
  end)

  it("unattributed is eligible only to an unattributed recorder", function()
    -- An unenrolled student keeps today's crash recovery; an enrolled one
    -- leaves alone every file it cannot prove is its own.
    assert.is_true(slog_ownership.is_eligible("unattributed", nil))
    assert.is_false(slog_ownership.is_eligible("unattributed", ALICE))
  end)
end)

describe("slog_ownership.select_eligible", function()
  --- A read function over a name -> text map that also records what was read,
  --- so a test can assert we did not even open a partner's log when we did not
  --- have to.
  local function reader(map)
    local reads = {}
    return function(path)
      reads[#reads + 1] = path
      return map[path]
    end,
      reads
  end

  it("returns the alphabetically LAST eligible file, not the alphabetically last file", function()
    local read, _ = reader({
      ["a.slog"] = session_start_line({ student_ref = ALICE }),
      ["z.slog"] = session_start_line({ student_ref = BOB }),
    })
    local selected = slog_ownership.select_eligible(read, { "a.slog", "z.slog" }, ALICE)
    assert.is_not_nil(selected)
    assert.equals("a.slog", selected.path)
  end)

  it("returns nil when every file in the directory is someone else's", function()
    local read, _ = reader({
      ["p1.slog"] = session_start_line({ student_ref = BOB }),
      ["p2.slog"] = session_start_line({ student_ref = BOB }),
    })
    assert.is_nil(slog_ownership.select_eligible(read, { "p1.slog", "p2.slog" }, ALICE))
  end)

  it("hands back the bytes it read, so the caller never re-reads the file", function()
    local text = session_start_line({ student_ref = ALICE })
    local read, reads = reader({ ["a.slog"] = text })
    local selected = slog_ownership.select_eligible(read, { "a.slog" }, ALICE)
    assert.equals(text, selected.text)
    assert.equals(1, #reads)
  end)

  it("the solo case still costs exactly one read", function()
    local read, reads = reader({
      ["a.slog"] = session_start_line(),
      ["b.slog"] = session_start_line(),
      ["c.slog"] = session_start_line(),
    })
    local selected = slog_ownership.select_eligible(read, { "a.slog", "b.slog", "c.slog" }, nil)
    assert.equals("c.slog", selected.path)
    assert.equals(1, #reads)
  end)

  it("an unreadable file is unattributed, so an enrolled recorder skips it", function()
    -- nil text cannot say whose the file is, and "cannot say" must never
    -- resolve to "ours" — this is the read_error path that used to rename.
    local read = function()
      return nil
    end
    assert.is_nil(slog_ownership.select_eligible(read, { "mystery.slog" }, ALICE))
  end)

  it("an unreadable file IS selectable by an unattributed recorder (crash recovery)", function()
    local read = function()
      return nil
    end
    local selected = slog_ownership.select_eligible(read, { "mystery.slog" }, nil)
    assert.equals("mystery.slog", selected.path)
    assert.is_nil(selected.text)
  end)

  it("a raising read is treated as unreadable, never propagated", function()
    local read = function()
      error("EIO")
    end
    assert.is_nil(slog_ownership.select_eligible(read, { "boom.slog" }, ALICE))
  end)

  it("is given no capability but reading — there is no write seam to misuse", function()
    -- Structural, not stylistic: the same rule watch/peer_watcher.lua follows.
    -- The scan's only argument-borne capability is `read_slog`, so no amount of
    -- getting the classification wrong can rename a partner's file from inside
    -- it. Pinned by asserting the module's whole public surface, so a later
    -- `rename`/`quarantine` helper added here fails this test rather than
    -- quietly re-opening bug 2.
    local surface = vim.tbl_keys(slog_ownership)
    table.sort(surface)
    assert.same({ "classify", "is_eligible", "select_eligible", "student_ref_of_slog_text" }, surface)
  end)
end)
