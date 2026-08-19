--- SessionHost: the single chaining chokepoint. Owns seq/prev_hash and
--- advances them for every emitted event. Mirrors log-core's session-host.ts.
local core_clock = require("provenance.core.clock")
local hash_chain = require("provenance.core.hash_chain")
local session_host = require("provenance.recorder.session.session_host")

describe("session_host.new", function()
  it("exposes session_id and t_start_ms captured at construction", function()
    local clock = core_clock.fixed(1000, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })
    assert.equals("sess-1", host.session_id)
    assert.equals(1000, host.t_start_ms)
  end)

  it("starts get_seq() at 0", function()
    local clock = core_clock.fixed(0, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })
    assert.equals(0, host.get_seq())
  end)
end)

describe("session_host.emit", function()
  it("first emit has seq 0 and GENESIS prev_hash", function()
    local clock = core_clock.fixed(0, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })

    local entry = host.emit("session.start", { foo = "bar" })

    assert.equals(0, entry.seq)
    assert.equals(hash_chain.GENESIS_PREV_HASH, entry.prev_hash)
    assert.equals("session.start", entry.kind)
    assert.same({ foo = "bar" }, entry.data)
  end)

  it("second emit chains onto the first and advances seq", function()
    local clock = core_clock.fixed(0, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })

    local entry1 = host.emit("doc.open", { path = "a.lua" })
    local entry2 = host.emit("doc.close", { path = "a.lua" })

    assert.equals(1, entry2.seq)
    assert.equals(entry1.hash, entry2.prev_hash)
    assert.are_not.equals(entry1.hash, entry2.hash)
  end)

  it("after emit, get_seq() reflects the advanced state", function()
    local clock = core_clock.fixed(0, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })

    host.emit("session.start", {})
    assert.equals(1, host.get_seq())
    host.emit("doc.open", { path = "a.lua" })
    assert.equals(2, host.get_seq())
  end)

  it("computes t as clock.now() - t_start rounded", function()
    local clock = core_clock.fixed(1000, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })

    clock.set_now(1000 + 250)
    local entry = host.emit("heartbeat", {})

    assert.equals(250, entry.t)
  end)

  it("clamps t to 0 when the clock goes backward relative to t_start", function()
    local clock = core_clock.fixed(1000, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })

    clock.set_now(500) -- before t_start
    local entry = host.emit("heartbeat", {})

    assert.equals(0, entry.t)
  end)

  it("uses clock.wall() for the wall field", function()
    local clock = core_clock.fixed(0, 1767225600800)
    local host = session_host.new({ session_id = "sess-1", clock = clock })

    local entry = host.emit("session.start", {})

    assert.equals("2026-01-01T00:00:00.800Z", entry.wall)
  end)

  it("calls on_entry with the produced entry", function()
    local clock = core_clock.fixed(0, 0)
    local captured
    local host = session_host.new({
      session_id = "sess-1",
      clock = clock,
      on_entry = function(entry)
        captured = entry
      end,
    })

    local entry = host.emit("session.start", {})

    assert.equals(entry, captured)
  end)

  it("advances chain state BEFORE invoking on_entry, even when on_entry errors", function()
    local clock = core_clock.fixed(0, 0)
    local captured_first

    local host = session_host.new({
      session_id = "sess-1",
      clock = clock,
      on_entry = function(entry)
        captured_first = entry
        error("boom")
      end,
    })

    local ok, err = pcall(host.emit, "session.start", {})
    assert.is_false(ok)
    assert.is_truthy(tostring(err):find("boom", 1, true))
    assert.is_not_nil(captured_first)

    -- Swap in a non-throwing on_entry for the next call, and prove state
    -- already advanced past the first (throwing) emit.
    host.on_entry = nil

    local entry2 = host.emit("session.end", {})
    assert.equals(1, entry2.seq)
    assert.equals(captured_first.hash, entry2.prev_hash)
  end)

  it("works with no on_entry provided", function()
    local clock = core_clock.fixed(0, 0)
    local host = session_host.new({ session_id = "sess-1", clock = clock })
    local entry = host.emit("session.start", {})
    assert.equals(0, entry.seq)
  end)
end)

--- CAPTURE-POLICY ENFORCEMENT AT THE CHAINING CHOKEPOINT (program spec §4).
---
--- The safety property under test: a suppressed event must consume NO sequence
--- number. Dropping an event AFTER chaining would leave a hole in the seq run,
--- and validation check 3 reads a hole as a DELETED ENTRY -- which would turn a
--- course's privacy setting into a tamper signal against the student. These
--- tests assert the seq run stays contiguous and the chain stays valid across
--- heavy suppression.
describe("session_host.emit capture-policy gate", function()
  local capture_policy = require("provenance.core.capture_policy")
  local policy_gate = require("provenance.recorder.session.policy_gate")
  local chain_validator = require("provenance.core.chain_validator")

  -- Every knob that still exists, all off. Note doc.open/doc.close are NOT here
  -- any more: they became floor kinds (doc.open carries the reconstruction
  -- seed), so the gated set is exactly selection/focus/terminal.
  local ALL_OFF = {
    capture = {
      selection_change = false,
      focus_change = false,
      terminal = false,
    },
  }

  local function host_with(policy_block)
    local entries = {}
    local host = session_host.new({
      session_id = "sess-policy",
      clock = core_clock.fixed(0, 0),
      policy_gate = policy_gate.new(capture_policy.resolve(policy_block)),
      on_entry = function(entry)
        table.insert(entries, entry)
      end,
    })
    return host, entries
  end

  it("a suppressed kind consumes NO seq and does not advance the chain", function()
    local host, entries = host_with(ALL_OFF)

    local first = host.emit("session.start", { a = 1 })
    local seq_before, hash_before = host.get_seq(), first.hash

    assert.is_nil(host.emit("selection.change", { line = 1 }))
    assert.is_nil(host.emit("focus.change", { focused = false }))
    assert.is_nil(host.emit("terminal.open", { id = 1 }))
    assert.is_nil(host.emit("terminal.command", { cmd = "ls" }))

    -- Nothing moved.
    assert.equals(seq_before, host.get_seq())
    assert.equals(1, #entries)

    -- and the next allowed event chains straight onto the first, with the very
    -- next seq -- no hole where the suppressed events would have been.
    local next_entry = host.emit("doc.change", { path = "a.lua" })
    assert.equals(seq_before, next_entry.seq)
    assert.equals(hash_before, next_entry.prev_hash)
  end)

  it("the seq run stays contiguous from 0 with suppression interleaved throughout", function()
    local host, entries = host_with(ALL_OFF)

    host.emit("session.start", {})
    for i = 1, 20 do
      -- Alternate allowed and suppressed kinds so any hole would show up.
      -- doc.open is deliberately in the ALLOWED column now: it is a floor kind.
      host.emit("selection.change", { i = i })
      host.emit("doc.change", { i = i })
      host.emit("doc.open", { i = i })
      host.emit("focus.change", { i = i })
      host.emit("doc.save", { i = i })
      host.emit("terminal.open", { i = i })
    end
    host.emit("session.end", { reason = "deactivate" })

    -- 1 start + 20*(doc.change + doc.open + doc.save) + 1 end
    assert.equals(62, #entries)
    for i, entry in ipairs(entries) do
      assert.equals(i - 1, entry.seq, "seq must be contiguous from 0; hole before index " .. i)
    end
  end)

  it("the resulting chain VALIDATES -- check 3 sees no deleted entry", function()
    -- The end-to-end statement of the invariant: run the real chain validator,
    -- the same one that backs validation check 3, over a heavily suppressed run.
    local host, entries = host_with(ALL_OFF)

    host.emit("session.start", {})
    for i = 1, 15 do
      host.emit("selection.change", { i = i })
      host.emit("terminal.command", { i = i })
      host.emit("doc.change", { i = i })
    end
    host.emit("session.end", { reason = "deactivate" })

    local res = chain_validator.validate_chain(entries)
    assert.is_true(res.ok, "chain must validate: " .. vim.inspect(res.break_ or {}))
  end)

  it("EVERY floor kind survives an all-off policy and is chained", function()
    local host, entries = host_with(ALL_OFF)
    for _, kind in ipairs(capture_policy.FLOOR_EVENT_KINDS) do
      assert.is_not_nil(host.emit(kind, {}), kind .. " is on the floor and must be recorded")
    end
    assert.equals(#capture_policy.FLOOR_EVENT_KINDS, #entries)
    assert.is_true(chain_validator.validate_chain(entries).ok)
  end)

  --- REPLACES the deleted inline-content redaction test. `inline_content` was
  --- retired, so `paste` and `fs.external_change` now reach the chain with their
  --- content intact under EVERY policy -- which is the property internal_move
  --- depends on to downgrade a large_paste flag.
  it("paste and external-change content reaches the chain intact under an all-off policy", function()
    local host, entries = host_with(ALL_OFF)

    local paste = host.emit("paste", { length = 6, sha256 = string.rep("c", 64), content = "secret" })
    assert.equals("secret", paste.data.content, "no policy may strip paste content any more")
    assert.equals(6, paste.data.length)
    assert.equals(string.rep("c", 64), paste.data.sha256)

    local ext = host.emit("fs.external_change", { new_content_size = 9, new_content = "rewritten" })
    assert.equals("rewritten", ext.data.new_content)
    assert.equals(9, ext.data.new_content_size)

    assert.equals(2, #entries)
    assert.is_true(chain_validator.validate_chain(entries).ok)
  end)

  it("with no gate injected, behaviour is exactly as before the policy existed", function()
    local entries = {}
    local host = session_host.new({
      session_id = "sess-nogate",
      clock = core_clock.fixed(0, 0),
      on_entry = function(entry) table.insert(entries, entry) end,
    })
    for _, kind in ipairs({ "session.start", "selection.change", "doc.open", "terminal.open" }) do
      assert.is_not_nil(host.emit(kind, {}))
    end
    assert.equals(4, #entries)
    assert.equals(4, host.get_seq())
  end)

  it("the default policy suppresses nothing", function()
    local host, entries = host_with(nil)
    local gated_count = 0
    for kind in pairs(capture_policy.POLICY_GATED_EVENT_KINDS) do
      assert.is_not_nil(host.emit(kind, {}), kind .. " must be recorded under the default policy")
      gated_count = gated_count + 1
    end
    assert.equals(4, gated_count, "the gated set is selection/focus/terminal.open/terminal.command")
    assert.equals(gated_count, #entries)
  end)
end)
