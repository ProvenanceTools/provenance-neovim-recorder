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
