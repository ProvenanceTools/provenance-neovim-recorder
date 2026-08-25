local chain_recovery = require("provenance.recorder.startup.chain_recovery")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local ndjson = require("provenance.core.ndjson")
local clock = require("provenance.core.clock")

local FIXED_NOW = "2026-05-19T14-30-00.000Z"

--- Wall clock of the session.start of a built chain, epoch ms
--- (2026-01-01T00:00:00.000Z), and one day in ms. Selection is by
--- `session.start.wall`, so every example that has more than one candidate
--- says which session actually ran last by choosing these.
local BASE_WALL_MS = 1767225600000
local DAY_MS = 86400000

local function fixed_now()
  return FIXED_NOW
end

--- Build an in-memory deps table backed by a map of slog name -> text.
--- `rename` records calls and defaults to succeeding; `list_slogs` returns
--- the map's keys (deliberately unsorted per test intent).
local function make_deps(opts)
  opts = opts or {}
  local slog_texts = opts.slog_texts or {}
  local names = opts.names or vim.tbl_keys(slog_texts)
  local rename_calls = {}
  local rename_result = opts.rename_result
  if rename_result == nil then
    rename_result = true
  end

  local deps = {
    list_slogs = opts.list_slogs or function()
      return names
    end,
    read_slog = opts.read_slog or function(path)
      return slog_texts[path]
    end,
    rename = opts.rename or function(from, to)
      rename_calls[#rename_calls + 1] = { from = from, to = to }
      return rename_result
    end,
    now = opts.now or fixed_now,
    -- The ownership signal. nil (the default, and what every example above
    -- uses) means an UNATTRIBUTED recorder, which is the pre-enrollment
    -- behaviour those examples were written against.
    own_student_ref = opts.own_student_ref,
  }
  return deps, rename_calls
end

--- Serialize a list of HashedEnvelope entries into slog text (NDJSON, one
--- json.canonicalize'd line per entry) — same shape as a real .slog file.
local function serialize(entries)
  local lines = {}
  for _, e in ipairs(entries) do
    lines[#lines + 1] = ndjson.serialize_entry(e)
  end
  return table.concat(lines)
end

--- A valid chain: session.start (data.session_id = id) ... optionally
--- ending on session.end. `middle_kind` lets a dangling case end on a
--- non-terminal event.
--- `start_wall_ms` sets the session.start wall; later entries step forward 1s
--- each so the chain's own monotonic-wall check still passes.
local function build_chain(session_id, with_end, start_wall_ms)
  local wall0 = start_wall_ms or BASE_WALL_MS
  local e0 = hc.chain_entry(
    hc.GENESIS_PREV_HASH,
    envelope.new(0, 0, clock.format_wall(wall0), "session.start", { session_id = session_id })
  )
  local e1 = hc.chain_entry(
    e0.hash,
    envelope.new(1, 1000, clock.format_wall(wall0 + 1000), "doc.change", { path = "a.py" })
  )
  local entries = { e0, e1 }
  if with_end then
    local e2 = hc.chain_entry(
      e1.hash,
      envelope.new(2, 2000, clock.format_wall(wall0 + 2000), "session.end", { reason = "seal" })
    )
    entries[#entries + 1] = e2
  end
  return entries
end

describe("chain_recovery.recover_previous_session", function()
  it("returns clean_start when there are no .slog files", function()
    local deps = make_deps({ slog_texts = {} })
    local decision = chain_recovery.recover_previous_session(deps)
    assert.same({ kind = "clean_start" }, decision)
  end)

  it("ignores non-.slog entries (e.g. .slog.meta) and returns clean_start if none remain", function()
    local deps = make_deps({
      names = { "session-a.slog.meta", "notes.txt" },
      slog_texts = {},
    })
    local decision = chain_recovery.recover_previous_session(deps)
    assert.same({ kind = "clean_start" }, decision)
  end)

  it("picks the .slog whose session.start wall is LATEST, not the alphabetically last", function()
    -- The filename uuid is minted independently of the session id (the two-uuid
    -- rule), so alphabetical order says nothing about which session ran last.
    -- All three chains here are valid; only the wall separates them, and the
    -- winner is the file that sorts FIRST.
    local deps = make_deps({
      names = { "session-b.slog", "session-a.slog", "session-c.slog" },
      slog_texts = {
        ["session-a.slog"] = serialize(build_chain("id-a", true, BASE_WALL_MS + 2 * DAY_MS)),
        ["session-b.slog"] = serialize(build_chain("id-b", true, BASE_WALL_MS)),
        ["session-c.slog"] = serialize(build_chain("id-c", true, BASE_WALL_MS + DAY_MS)),
      },
    })
    local decision = chain_recovery.recover_previous_session(deps)
    assert.same({ kind = "previous_session_complete", prev_session_id = "id-a" }, decision)
  end)

  it("falls back to the alphabetically last .slog when nothing has a parseable wall", function()
    -- Every file is unorderable garbage. There is nothing to sort by, and the
    -- quarantine path still needs one deterministic target.
    local deps, rename_calls = make_deps({
      names = { "session-b.slog", "session-a.slog", "session-c.slog" },
      slog_texts = {
        ["session-a.slog"] = "garbage that would fail to parse {not ndjson",
        ["session-b.slog"] = "garbage that would fail to parse {not ndjson",
        ["session-c.slog"] = "garbage that would fail to parse {not ndjson",
      },
    })
    local decision = chain_recovery.recover_previous_session(deps)
    assert.equals("previous_session_corrupt", decision.kind)
    assert.equals(1, #rename_calls)
    assert.equals("session-c.slog", rename_calls[1].from)
  end)

  it("returns previous_session_complete when the chain's last entry is session.end", function()
    local chain = build_chain("prev-id", true)
    local deps = make_deps({ slog_texts = { ["session-only.slog"] = serialize(chain) } })
    local decision = chain_recovery.recover_previous_session(deps)
    assert.same({ kind = "previous_session_complete", prev_session_id = "prev-id" }, decision)
  end)

  it("returns previous_session_dangling when the chain has no clean session.end", function()
    local chain = build_chain("prev-id", false)
    local deps = make_deps({ slog_texts = { ["session-only.slog"] = serialize(chain) } })
    local decision = chain_recovery.recover_previous_session(deps)
    assert.same(
      { kind = "previous_session_dangling", prev_session_id = "prev-id", dangling_path = "session-only.slog" },
      decision
    )
  end)

  it("quarantines and returns previous_session_corrupt when the slog fails to parse", function()
    local deps, rename_calls = make_deps({
      slog_texts = { ["session-only.slog"] = "{not ndjson" },
    })
    local decision = chain_recovery.recover_previous_session(deps)
    local expected_path = "session-only.slog.corrupt-" .. FIXED_NOW
    assert.same({ kind = "previous_session_corrupt", quarantined_path = expected_path }, decision)
    assert.equals(1, #rename_calls)
    assert.same({ from = "session-only.slog", to = expected_path }, rename_calls[1])
  end)

  it("quarantines and returns previous_session_corrupt when the hash chain is broken", function()
    local chain = build_chain("prev-id", true)
    -- Tamper an entry's hash so validate_chain fails.
    chain[2].hash = ("00"):rep(32)
    local deps, rename_calls = make_deps({
      slog_texts = { ["session-only.slog"] = serialize(chain) },
    })
    local decision = chain_recovery.recover_previous_session(deps)
    local expected_path = "session-only.slog.corrupt-" .. FIXED_NOW
    assert.same({ kind = "previous_session_corrupt", quarantined_path = expected_path }, decision)
    assert.equals(1, #rename_calls)
  end)

  it("quarantines and returns previous_session_corrupt when the first entry is not session.start", function()
    -- A valid-shaped, self-consistent chain, but the first entry is doc.change.
    local e0 = hc.chain_entry(
      hc.GENESIS_PREV_HASH,
      envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "doc.change", { path = "a.py" })
    )
    local e1 = hc.chain_entry(
      e0.hash,
      envelope.new(1, 1000, "2026-01-01T00:00:01.000Z", "session.end", { reason = "seal" })
    )
    local deps, rename_calls = make_deps({
      slog_texts = { ["session-only.slog"] = serialize({ e0, e1 }) },
    })
    local decision = chain_recovery.recover_previous_session(deps)
    local expected_path = "session-only.slog.corrupt-" .. FIXED_NOW
    assert.same({ kind = "previous_session_corrupt", quarantined_path = expected_path }, decision)
    assert.equals(1, #rename_calls)
  end)

  it("quarantines and returns previous_session_corrupt when read_slog fails (returns nil)", function()
    local deps, rename_calls = make_deps({
      names = { "session-only.slog" },
      read_slog = function()
        return nil
      end,
    })
    local decision = chain_recovery.recover_previous_session(deps)
    local expected_path = "session-only.slog.corrupt-" .. FIXED_NOW
    assert.same({ kind = "previous_session_corrupt", quarantined_path = expected_path }, decision)
    assert.equals(1, #rename_calls)
  end)

  it("still returns previous_session_corrupt when the rename itself fails (best-effort quarantine)", function()
    local failing_rename_calls = {}
    local deps = make_deps({
      slog_texts = { ["session-only.slog"] = "{not ndjson" },
      rename = function(from, to)
        failing_rename_calls[#failing_rename_calls + 1] = { from = from, to = to }
        return false, "permission denied"
      end,
    })
    local decision = chain_recovery.recover_previous_session(deps)
    local expected_path = "session-only.slog.corrupt-" .. FIXED_NOW
    assert.same({ kind = "previous_session_corrupt", quarantined_path = expected_path }, decision)
    assert.equals(1, #failing_rename_calls)
  end)

  it("never emits a chain.broken decision — the returned decision is one of exactly 4 kinds", function()
    local kinds = {
      clean_start = true,
      previous_session_complete = true,
      previous_session_dangling = true,
      previous_session_corrupt = true,
    }
    local cases = {
      make_deps({ slog_texts = {} }),
      make_deps({ slog_texts = { ["s.slog"] = serialize(build_chain("id", true)) } }),
      make_deps({ slog_texts = { ["s.slog"] = serialize(build_chain("id", false)) } }),
      make_deps({ slog_texts = { ["s.slog"] = "{not ndjson" } }),
    }
    for _, deps in ipairs(cases) do
      local decision = chain_recovery.recover_previous_session(deps)
      assert.is_true(kinds[decision.kind] == true)
      assert.are_not.equal("chain.broken", decision.kind)
    end
  end)

  it("never throws even if a dep raises an error", function()
    local deps = make_deps({
      list_slogs = function()
        error("boom: deps blew up")
      end,
    })
    local ok, decision = pcall(chain_recovery.recover_previous_session, deps)
    assert.is_true(ok)
    assert.equals("clean_start", decision.kind)
  end)
end)

--- ===========================================================================
--- THE SHARED REPO — decision-log bug 2
--- ===========================================================================
---
--- `.provenance/` is committed, so a partner's `.slog` arrives by `git pull`
--- and lands in the same directory this recorder scans at startup. Every
--- example below is a real shape from a two-partner CS 61B repo, and the thing
--- being asserted is always the same: this recorder does not touch, and does
--- not claim, a file it cannot prove is its own.
---
--- Note what a passing run looks like on the OLD code. Each of these ended in
--- either a `rename` of the partner's only record — which `commands/seal.lua`
--- then drops from the submission, with git blaming the victim's partner for
--- it — or a `prev_session_id` naming a stranger's session.
describe("chain_recovery.recover_previous_session — shared repo ownership", function()
  local ALICE = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
  local BOB = "9a7b1c2d-3e4f-4a5b-8c9d-0e1f2a3b4c5d"

  --- A real chained slog whose session.start carries `student_ref`.
  --- `with_end = false` leaves it DANGLING, which is what a partner whose
  --- editor is open right now looks like on disk.
  local function build_attributed_chain(session_id, student_ref, with_end, start_wall_ms)
    local data = { session_id = session_id }
    if student_ref ~= nil then
      data.identity = {
        enrollment = { student_ref = student_ref, course_id = "berkeley-cs61b" },
      }
    end
    local wall0 = start_wall_ms or BASE_WALL_MS
    local e0 = hc.chain_entry(
      hc.GENESIS_PREV_HASH,
      envelope.new(0, 0, clock.format_wall(wall0), "session.start", data)
    )
    local e1 = hc.chain_entry(
      e0.hash,
      envelope.new(1, 1000, clock.format_wall(wall0 + 1000), "doc.change", { path = "a.py" })
    )
    local entries = { e0, e1 }
    if with_end then
      entries[#entries + 1] = hc.chain_entry(
        e1.hash,
        envelope.new(2, 2000, clock.format_wall(wall0 + 2000), "session.end", { reason = "seal" })
      )
    end
    return serialize(entries)
  end

  --- A partner's log that is mid-write, or truncated by a checkout, but whose
  --- FIRST LINE is intact and names them. That is the realistic shape: the
  --- header is written once at session start; the tail is what a copy catches
  --- half-done — and it is precisely the shape the old code renamed.
  local function truncated_partner_log(student_ref, start_wall_ms)
    local full = build_attributed_chain("bob-live", student_ref, false, start_wall_ms)
    return full:sub(1, #full - 20)
  end

  it("leaves a partner's unparseable .slog untouched, and does not chain to it", function()
    local deps, rename_calls = make_deps({
      names = { "session-zzz-bob.slog" },
      slog_texts = { ["session-zzz-bob.slog"] = truncated_partner_log(BOB) },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    -- Not renamed. This is the whole bug: the partner's only record survives.
    assert.equals(0, #rename_calls)
    -- Not adopted either — no back-pointer to a session that is not ours.
    assert.same({ kind = "clean_start" }, decision)
  end)

  it("a partner's log does not become 'the previous session', even as the newest file", function()
    -- Alice's own crashed session sorts FIRST and is the OLDER of the two;
    -- Bob's sorts last and is the more recent. Ownership outranks ordering, so
    -- neither the filename nor the wall can promote a file this recorder cannot
    -- prove is its own.
    local deps, rename_calls = make_deps({
      names = { "session-aaa-alice.slog", "session-zzz-bob.slog" },
      slog_texts = {
        ["session-aaa-alice.slog"] = build_attributed_chain("alice-crashed", ALICE, false, BASE_WALL_MS),
        ["session-zzz-bob.slog"] = build_attributed_chain("bob-session", BOB, false, BASE_WALL_MS + DAY_MS),
      },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_dangling", decision.kind)
    assert.equals("alice-crashed", decision.prev_session_id)
    assert.equals("session-aaa-alice.slog", decision.dangling_path)
    assert.equals(0, #rename_calls)
  end)

  it("among this contributor's OWN files the latest wall wins, not the last filename", function()
    -- The back-pointer has to name the session that actually preceded this one.
    -- Alice's most recent session sorts first, her older completed one sorts
    -- last, and Bob's — newer than both — sorts in the middle.
    local deps, rename_calls = make_deps({
      names = { "session-a-alice.slog", "session-m-bob.slog", "session-z-alice.slog" },
      slog_texts = {
        ["session-a-alice.slog"] = build_attributed_chain("alice-newest", ALICE, false, BASE_WALL_MS + 2 * DAY_MS),
        ["session-m-bob.slog"] = build_attributed_chain("bob-newest", BOB, false, BASE_WALL_MS + 3 * DAY_MS),
        ["session-z-alice.slog"] = build_attributed_chain("alice-older", ALICE, true, BASE_WALL_MS),
      },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_dangling", decision.kind)
    assert.equals("alice-newest", decision.prev_session_id)
    assert.equals(0, #rename_calls)
  end)

  it("prev_session_id skips a partner and names THIS contributor's own previous session", function()
    -- Three partner logs interleaved around one of ours, with a partner's
    -- sorting last. The back-pointer must name a session of the same
    -- contributor or it asserts a relationship the evidence does not support —
    -- and a false one poisons the analyzer's deletion detector, which reads a
    -- missing middle session off the next session's back-pointer.
    local deps, rename_calls = make_deps({
      names = {
        "session-b-bob.slog",
        "session-c-alice.slog",
        "session-a-bob.slog",
        "session-d-bob.slog",
      },
      slog_texts = {
        ["session-a-bob.slog"] = build_attributed_chain("bob-1", BOB, true),
        ["session-b-bob.slog"] = build_attributed_chain("bob-2", BOB, false),
        ["session-c-alice.slog"] = build_attributed_chain("alice-crashed", ALICE, false),
        ["session-d-bob.slog"] = build_attributed_chain("bob-3", BOB, false),
      },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_dangling", decision.kind)
    assert.equals("alice-crashed", decision.prev_session_id)
    assert.equals(0, #rename_calls)
  end)

  it("an enrolled recorder never quarantines an UNATTRIBUTED log", function()
    -- A 1.x log, or one written before either student enrolled. We cannot
    -- prove it is ours, so we do not touch it: losing a back-pointer costs a
    -- link, renaming someone's only record costs the evidence.
    local deps, rename_calls = make_deps({
      names = { "session-mystery.slog" },
      slog_texts = { ["session-mystery.slog"] = "{not ndjson garbage" },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals(0, #rename_calls)
    assert.same({ kind = "clean_start" }, decision)
  end)

  it("an enrolled recorder does not even LINK an unattributed, perfectly valid log", function()
    local deps, rename_calls = make_deps({
      names = { "session-mystery.slog" },
      slog_texts = { ["session-mystery.slog"] = build_attributed_chain("unknown-owner", nil, false) },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.same({ kind = "clean_start" }, decision)
    assert.equals(0, #rename_calls)
  end)

  it("an unenrolled recorder still recovers its own crash", function()
    -- The module's whole reason to exist. Nobody in this directory has
    -- enrolled, so it is indistinguishable from a solo one, and refusing to act
    -- would silently switch crash recovery off for every student who has not
    -- enrolled yet.
    local deps, rename_calls = make_deps({
      names = { "session-only.slog" },
      slog_texts = { ["session-only.slog"] = build_attributed_chain("crashed-id", nil, false) },
      own_student_ref = nil,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_dangling", decision.kind)
    assert.equals("crashed-id", decision.prev_session_id)
    assert.equals(0, #rename_calls)
  end)

  it("an ENROLLED recorder still recovers its OWN crash", function()
    local deps, rename_calls = make_deps({
      names = { "session-only.slog" },
      slog_texts = { ["session-only.slog"] = build_attributed_chain("crashed-id", ALICE, false) },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_dangling", decision.kind)
    assert.equals("crashed-id", decision.prev_session_id)
    assert.equals(0, #rename_calls)
  end)

  it("an unenrolled recorder still quarantines its own corrupt log", function()
    local deps, rename_calls = make_deps({
      names = { "session-only.slog" },
      slog_texts = { ["session-only.slog"] = "{not ndjson" },
      own_student_ref = nil,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_corrupt", decision.kind)
    assert.equals(1, #rename_calls)
    assert.equals("session-only.slog", rename_calls[1].from)
  end)

  it("an unenrolled recorder leaves an ENROLLED partner's log alone", function()
    -- The asymmetric `foreign` case. We hold no identity, so we cannot claim to
    -- be the contributor this file names — and this is the configuration that
    -- protects a partner who enrolled from a partner who has not.
    local deps, rename_calls = make_deps({
      names = { "session-bob.slog" },
      slog_texts = { ["session-bob.slog"] = truncated_partner_log(BOB) },
      own_student_ref = nil,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.same({ kind = "clean_start" }, decision)
    assert.equals(0, #rename_calls)
  end)

  it("quarantines OUR OWN corrupt log even with a partner's file sitting next to it", function()
    -- The fix must not trade bug 2 for a dead recovery path: an enrolled
    -- student whose own log really is damaged still gets it quarantined, and
    -- the partner's file is still not touched.
    local own_head = build_attributed_chain("alice-1", ALICE, false):match("^[^\n]*\n")
    local deps, rename_calls = make_deps({
      names = { "session-a-alice.slog", "session-z-bob.slog" },
      slog_texts = {
        -- Alice's own log: valid first line naming her, garbage after it.
        ["session-a-alice.slog"] = own_head .. "{not ndjson\n",
        ["session-z-bob.slog"] = truncated_partner_log(BOB),
      },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_corrupt", decision.kind)
    assert.equals(1, #rename_calls)
    assert.equals("session-a-alice.slog", rename_calls[1].from)
  end)

  it("a directory of nothing but partner logs is a clean start, with nothing renamed", function()
    local deps, rename_calls = make_deps({
      names = { "session-a-bob.slog", "session-b-bob.slog", "session-c-bob.slog" },
      slog_texts = {
        ["session-a-bob.slog"] = build_attributed_chain("bob-1", BOB, true),
        ["session-b-bob.slog"] = "{mid-write garbage",
        ["session-c-bob.slog"] = truncated_partner_log(BOB),
      },
      own_student_ref = ALICE,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.same({ kind = "clean_start" }, decision)
    assert.equals(0, #rename_calls)
  end)

  it("the residual gap is real: two UNENROLLED partners cannot be told apart", function()
    -- Documented rather than hidden. With neither side enrolled every file is
    -- `unattributed`, no signal exists that could separate them, and the old
    -- behaviour is what remains. This test exists so the gap is visible in the
    -- suite, and so closing it (enrollment, or peer witnessing) shows up here
    -- as a deliberate change rather than a surprise.
    -- The partner's log is the most recent thing in the directory and its first
    -- line is intact, so wall order selects it; the truncated tail then fails to
    -- parse and the quarantine lands on their evidence.
    local partner_head =
      build_attributed_chain("partner-live", nil, false, BASE_WALL_MS + DAY_MS):match("^[^\n]*\n")
    local deps, rename_calls = make_deps({
      names = { "session-a-mine.slog", "session-z-partner.slog" },
      slog_texts = {
        ["session-a-mine.slog"] = build_attributed_chain("mine", nil, false, BASE_WALL_MS),
        ["session-z-partner.slog"] = partner_head .. "{partner log, mid-write",
      },
      own_student_ref = nil,
    })

    local decision = chain_recovery.recover_previous_session(deps)

    assert.equals("previous_session_corrupt", decision.kind)
    assert.equals(1, #rename_calls)
    assert.equals("session-z-partner.slog", rename_calls[1].from)
  end)
end)
