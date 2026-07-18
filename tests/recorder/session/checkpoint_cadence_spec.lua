--- Checkpoint cadence counter: pure counter that returns true every N-th call.
--- Used to decide when to emit a signed checkpoint during recording.
local checkpoint_cadence = require("provenance.recorder.session.checkpoint_cadence")

describe("checkpoint_cadence.new", function()
  it("defaults to interval 100 when nil", function()
    local cadence = checkpoint_cadence.new()
    assert.is_not_nil(cadence)
    -- 99 calls return false
    for i = 1, 99 do
      assert.is_false(cadence.on_entry_appended(), "call " .. i .. " should return false")
    end
    -- 100th call returns true
    assert.is_true(cadence.on_entry_appended())
    -- 101st call returns false again (reset happened)
    assert.is_false(cadence.on_entry_appended())
  end)

  it("accepts a custom interval", function()
    local cadence = checkpoint_cadence.new(3)
    assert.is_false(cadence.on_entry_appended())
    assert.is_false(cadence.on_entry_appended())
    assert.is_true(cadence.on_entry_appended())
    assert.is_false(cadence.on_entry_appended())
    assert.is_false(cadence.on_entry_appended())
    assert.is_true(cadence.on_entry_appended())
  end)

  it("supports interval=1 (every call returns true)", function()
    local cadence = checkpoint_cadence.new(1)
    assert.is_true(cadence.on_entry_appended())
    assert.is_true(cadence.on_entry_appended())
    assert.is_true(cadence.on_entry_appended())
  end)

  it("returns independent instances (no shared state)", function()
    local cadence1 = checkpoint_cadence.new(2)
    local cadence2 = checkpoint_cadence.new(2)

    -- Advance cadence1 to 1
    assert.is_false(cadence1.on_entry_appended())

    -- cadence2 should still be at 0 (independent state)
    assert.is_false(cadence2.on_entry_appended()) -- 1st call, counter=1, returns false
    assert.is_true(cadence2.on_entry_appended()) -- 2nd call, counter=2, returns true and resets
    assert.is_false(cadence2.on_entry_appended()) -- 3rd call, counter=1, returns false
    assert.is_true(cadence2.on_entry_appended()) -- 4th call, counter=2, returns true and resets

    -- cadence1 should be independent, still waiting for call 2
    assert.is_true(cadence1.on_entry_appended()) -- 2nd call for cadence1, counter=2, returns true and resets
  end)

  it("errors on interval <= 0", function()
    local ok1 = pcall(checkpoint_cadence.new, 0)
    assert.is_false(ok1, "interval=0 should error")

    local ok2 = pcall(checkpoint_cadence.new, -1)
    assert.is_false(ok2, "interval=-1 should error")

    local ok3 = pcall(checkpoint_cadence.new, -100)
    assert.is_false(ok3, "interval=-100 should error")
  end)

  it("errors on non-number interval", function()
    local ok1 = pcall(checkpoint_cadence.new, "100")
    assert.is_false(ok1, "string interval should error")

    local ok2 = pcall(checkpoint_cadence.new, {})
    assert.is_false(ok2, "table interval should error")

    local ok3 = pcall(checkpoint_cadence.new, nil)
    -- nil is OK - it should use default 100
    assert.is_true(ok3, "nil interval should use default")
  end)

  it("errors on non-integer interval (float)", function()
    local ok = pcall(checkpoint_cadence.new, 3.5)
    assert.is_false(ok, "non-integer interval should error")
  end)

  it("on_entry_appended increments counter and resets on threshold", function()
    local cadence = checkpoint_cadence.new(5)

    -- Call 1-4: should return false
    for i = 1, 4 do
      assert.is_false(cadence.on_entry_appended())
    end

    -- Call 5: should return true
    assert.is_true(cadence.on_entry_appended())

    -- Call 6: should return false again (counter reset to 1)
    assert.is_false(cadence.on_entry_appended())

    -- Call 7-10: return false
    for i = 7, 9 do
      assert.is_false(cadence.on_entry_appended())
    end

    -- Call 10: should return true
    assert.is_true(cadence.on_entry_appended())
  end)
end)
