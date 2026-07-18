local chain_recovery = require("provenance.recorder.startup.chain_recovery")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local ndjson = require("provenance.core.ndjson")

local FIXED_NOW = "2026-05-19T14-30-00.000Z"

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
local function build_chain(session_id, with_end)
  local e0 = hc.chain_entry(
    hc.GENESIS_PREV_HASH,
    envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.start", { session_id = session_id })
  )
  local e1 = hc.chain_entry(
    e0.hash,
    envelope.new(1, 1000, "2026-01-01T00:00:01.000Z", "doc.change", { path = "a.py" })
  )
  local entries = { e0, e1 }
  if with_end then
    local e2 = hc.chain_entry(
      e1.hash,
      envelope.new(2, 2000, "2026-01-01T00:00:02.000Z", "session.end", { reason = "seal" })
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

  it("picks the alphabetically-last .slog when unsorted and multiple exist", function()
    local chain_c = build_chain("id-c", true)
    local deps = make_deps({
      names = { "session-b.slog", "session-a.slog", "session-c.slog" },
      slog_texts = {
        ["session-a.slog"] = "garbage that would fail to parse {not ndjson",
        ["session-b.slog"] = "garbage that would fail to parse {not ndjson",
        ["session-c.slog"] = serialize(chain_c),
      },
    })
    local decision = chain_recovery.recover_previous_session(deps)
    assert.same({ kind = "previous_session_complete", prev_session_id = "id-c" }, decision)
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
