local disk_full_handler = require("provenance.recorder.failure.disk_full_handler")

--- Build a fresh set of injected callbacks with call counters, plus a handler
--- wired to them. Keeps each test's spies isolated.
local function make_handler(opts)
  opts = opts or {}
  local notify_calls = {}
  local degraded_calls = {}

  local handler = disk_full_handler.new({
    ring_capacity = opts.ring_capacity,
    notify = function(message)
      table.insert(notify_calls, message)
    end,
    on_degraded = function(data)
      table.insert(degraded_calls, data)
    end,
  })

  return handler, notify_calls, degraded_calls
end

describe("disk_full_handler", function()
  describe("degrade flips once (idempotent)", function()
    it("starts not degraded", function()
      local handler = make_handler()
      assert.is_false(handler.is_degraded())
    end)

    it("first handle_write_error() flips degraded, notifies once, emits on_degraded once", function()
      local handler, notify_calls, degraded_calls = make_handler()

      handler.handle_write_error("ENOSPC")

      assert.is_true(handler.is_degraded())
      assert.equals(1, #notify_calls)
      assert.equals(1, #degraded_calls)
      assert.equals("disk_full", degraded_calls[1].reason)
    end)

    it("second handle_write_error() is a no-op: no re-notify, no re-emit", function()
      local handler, notify_calls, degraded_calls = make_handler()

      handler.handle_write_error("ENOSPC")
      handler.handle_write_error("ENOSPC")
      handler.handle_write_error("EACCES") -- v1: any write error is treated as disk-full

      assert.is_true(handler.is_degraded())
      assert.equals(1, #notify_calls)
      assert.equals(1, #degraded_calls)
    end)
  end)

  describe("enqueue before degrade", function()
    it("returns false — not retained, normal writer path handles it", function()
      local handler = make_handler()
      local retained = handler.enqueue({ kind = "doc.change" })
      assert.is_false(retained)
    end)

    it("returns false even for a critical kind, since we are not degraded yet", function()
      local handler = make_handler()
      local retained = handler.enqueue({ kind = "session.start" })
      assert.is_false(retained)
    end)
  end)

  describe("after degrade, only CRITICAL_KINDS retained", function()
    local critical_kinds = {
      "session.start",
      "session.end",
      "fs.external_change",
      "chain.broken",
      "recorder.degraded",
      "recorder.recovered_from_corruption",
    }

    local noncritical_kinds = {
      "doc.change",
      "doc.open",
      "paste",
      "session.heartbeat",
      "terminal.open",
      "git.event",
      "ext.snapshot",
    }

    for _, kind in ipairs(critical_kinds) do
      it("retains critical kind: " .. kind, function()
        local handler = make_handler()
        handler.handle_write_error("ENOSPC")
        local retained = handler.enqueue({ kind = kind })
        assert.is_true(retained)
      end)
    end

    for _, kind in ipairs(noncritical_kinds) do
      it("drops non-critical kind: " .. kind, function()
        local handler = make_handler()
        handler.handle_write_error("ENOSPC")
        local retained = handler.enqueue({ kind = kind })
        assert.is_false(retained)
      end)
    end
  end)

  describe("FIFO eviction at capacity", function()
    it("keeps only the last N entries, oldest evicted first", function()
      local handler = make_handler({ ring_capacity = 3 })
      handler.handle_write_error("ENOSPC")

      handler.enqueue({ kind = "session.start", marker = 1 })
      handler.enqueue({ kind = "session.start", marker = 2 })
      handler.enqueue({ kind = "session.start", marker = 3 })
      handler.enqueue({ kind = "session.start", marker = 4 })

      local snapshot = handler.ring_snapshot()
      assert.equals(3, #snapshot)
      assert.equals(2, snapshot[1].marker)
      assert.equals(3, snapshot[2].marker)
      assert.equals(4, snapshot[3].marker)
    end)
  end)

  describe("ring_snapshot is a copy", function()
    it("mutating a snapshot does not affect the internal ring or later snapshots", function()
      local handler = make_handler({ ring_capacity = 5 })
      handler.handle_write_error("ENOSPC")
      handler.enqueue({ kind = "session.start", marker = 1 })

      local snapshot1 = handler.ring_snapshot()
      table.insert(snapshot1, { kind = "session.start", marker = "intruder" })
      table.remove(snapshot1, 1)

      local snapshot2 = handler.ring_snapshot()
      assert.equals(1, #snapshot2)
      assert.equals(1, snapshot2[1].marker)
    end)
  end)

  describe("CRITICAL_KINDS is exactly the 6 listed", function()
    it("contains exactly the 6 critical kinds, no more, no less", function()
      local expected = {
        ["session.start"] = true,
        ["session.end"] = true,
        ["fs.external_change"] = true,
        ["chain.broken"] = true,
        ["recorder.degraded"] = true,
        ["recorder.recovered_from_corruption"] = true,
      }

      local count = 0
      for kind, _ in pairs(disk_full_handler.CRITICAL_KINDS) do
        assert.is_true(expected[kind] ~= nil, "unexpected kind in CRITICAL_KINDS: " .. tostring(kind))
        count = count + 1
      end
      assert.equals(6, count)

      for kind, _ in pairs(expected) do
        assert.is_true(disk_full_handler.CRITICAL_KINDS[kind], "missing expected kind: " .. kind)
      end

      -- Sampling of non-critical kinds explicitly absent.
      assert.is_nil(disk_full_handler.CRITICAL_KINDS["doc.change"])
      assert.is_nil(disk_full_handler.CRITICAL_KINDS["paste"])
      assert.is_nil(disk_full_handler.CRITICAL_KINDS["session.heartbeat"])
    end)
  end)

  describe("never throws", function()
    it("handle_write_error tolerates nil error", function()
      local handler = make_handler()
      assert.has_no.errors(function()
        handler.handle_write_error(nil)
      end)
      assert.is_true(handler.is_degraded())
    end)

    it("enqueue tolerates an entry with a missing kind", function()
      local handler = make_handler()
      handler.handle_write_error("ENOSPC")
      local ok
      assert.has_no.errors(function()
        ok = handler.enqueue({})
      end)
      assert.is_false(ok)
    end)
  end)
end)
