--- checkpoint_scheduler.new: ordered async checkpoint scheduler (Plan 8,
--- Task 2). `schedule(seq, hash)` is non-blocking — it enqueues and defers
--- sign+persist to the event loop via `vim.schedule`, keeping ed25519
--- signing off the `on_lines` hot path. `drain()` synchronously processes
--- everything queued right now, in order, so `session.stop` can guarantee
--- every pending checkpoint is persisted before the meta file closes.
local checkpoint_scheduler = require("provenance.recorder.session.checkpoint_scheduler")

--- Build a fake `sign` that records calls and returns a signed checkpoint
--- shape matching `core.checkpoint.sign(seq, hash, privkey)`.
local function fake_sign(sign_calls)
  return function(seq, hash)
    table.insert(sign_calls, { seq = seq, hash = hash })
    return { seq = seq, hash = hash, sig = "fakesig-" .. tostring(seq) }
  end
end

local function fake_persist(persisted)
  return function(cp)
    table.insert(persisted, cp)
  end
end

describe("checkpoint_scheduler.new", function()
  local scheduler

  after_each(function()
    if scheduler then
      -- Drain to flush anything left queued so no vim.schedule callback
      -- leaks past the test (would show up in a later test or block exit).
      pcall(scheduler.drain)
      scheduler = nil
    end
  end)

  it("one checkpoint: drain() signs then persists it, in that order", function()
    local sign_calls = {}
    local persisted = {}
    scheduler = checkpoint_scheduler.new({
      sign = fake_sign(sign_calls),
      persist = fake_persist(persisted),
    })

    scheduler.schedule(99, "hash-99")
    scheduler.drain()

    assert.equals(1, #sign_calls)
    assert.equals(99, sign_calls[1].seq)
    assert.equals("hash-99", sign_calls[1].hash)

    assert.equals(1, #persisted)
    assert.equals(99, persisted[1].seq)
    assert.equals("hash-99", persisted[1].hash)
    assert.equals("fakesig-99", persisted[1].sig)
  end)

  it("two checkpoints: drain() persists them in FIFO order (seq 99 before seq 199)", function()
    local sign_calls = {}
    local persisted = {}
    scheduler = checkpoint_scheduler.new({
      sign = fake_sign(sign_calls),
      persist = fake_persist(persisted),
    })

    scheduler.schedule(99, "hash-99")
    scheduler.schedule(199, "hash-199")
    scheduler.drain()

    assert.equals(2, #persisted)
    assert.equals(99, persisted[1].seq)
    assert.equals(199, persisted[2].seq)
  end)

  it("schedule() is non-blocking: without drain(), a vim.schedule flush eventually persists it", function()
    local sign_calls = {}
    local persisted = {}
    scheduler = checkpoint_scheduler.new({
      sign = fake_sign(sign_calls),
      persist = fake_persist(persisted),
    })

    scheduler.schedule(99, "hash-99")
    -- No drain() call here: schedule() must return immediately without
    -- signing/persisting inline. Assert nothing happened synchronously...
    assert.equals(0, #persisted)

    -- ...then prove the event loop eventually processes it.
    vim.wait(200, function()
      return #persisted > 0
    end)

    assert.equals(1, #persisted)
    assert.equals(99, persisted[1].seq)
  end)

  it("an erroring sign on the first item does not wedge the queue: on_error fires once, second item still persists", function()
    local errors = {}
    local persisted = {}
    local call_n = 0
    scheduler = checkpoint_scheduler.new({
      sign = function(seq, hash)
        call_n = call_n + 1
        if call_n == 1 then
          error("sign failed for seq " .. seq)
        end
        return { seq = seq, hash = hash, sig = "fakesig-" .. tostring(seq) }
      end,
      persist = fake_persist(persisted),
      on_error = function(err)
        table.insert(errors, err)
      end,
    })

    scheduler.schedule(99, "hash-99")
    scheduler.schedule(199, "hash-199")
    scheduler.drain()

    assert.equals(1, #errors)
    assert.equals(1, #persisted)
    assert.equals(199, persisted[1].seq)
  end)

  it("an erroring persist does not wedge the queue: on_error fires, subsequent items still persist", function()
    local errors = {}
    local persisted = {}
    local call_n = 0
    scheduler = checkpoint_scheduler.new({
      sign = fake_sign({}),
      persist = function(cp)
        call_n = call_n + 1
        if call_n == 1 then
          error("persist failed for seq " .. cp.seq)
        end
        table.insert(persisted, cp)
      end,
      on_error = function(err)
        table.insert(errors, err)
      end,
    })

    scheduler.schedule(99, "hash-99")
    scheduler.schedule(199, "hash-199")
    scheduler.drain()

    assert.equals(1, #errors)
    assert.equals(1, #persisted)
    assert.equals(199, persisted[1].seq)
  end)

  it("drain() on an empty queue is a no-op: no error, no sign/persist calls", function()
    local sign_calls = {}
    local persisted = {}
    scheduler = checkpoint_scheduler.new({
      sign = fake_sign(sign_calls),
      persist = fake_persist(persisted),
    })

    assert.has_no.errors(function()
      scheduler.drain()
    end)

    assert.equals(0, #sign_calls)
    assert.equals(0, #persisted)
  end)

  it("schedule() then immediate drain() processes exactly once, even though a vim.schedule flush was also queued", function()
    local sign_calls = {}
    local persisted = {}
    scheduler = checkpoint_scheduler.new({
      sign = fake_sign(sign_calls),
      persist = fake_persist(persisted),
    })

    scheduler.schedule(99, "hash-99")
    scheduler.drain()

    -- Let any still-pending vim.schedule callback run too (it should find
    -- the queue empty and do nothing further).
    vim.wait(50, function()
      return false
    end)

    assert.equals(1, #sign_calls)
    assert.equals(1, #persisted)
  end)

  it("on_error is optional: an error with no on_error given does not throw out of drain()", function()
    local persisted = {}
    scheduler = checkpoint_scheduler.new({
      sign = function()
        error("boom")
      end,
      persist = fake_persist(persisted),
    })

    scheduler.schedule(99, "hash-99")
    assert.has_no.errors(function()
      scheduler.drain()
    end)
    assert.equals(0, #persisted)
  end)
end)
