--- ExplanationTagger: single-slot time-window store for marking formatter/git
--- operations during external-change detection (Plan 5).
---
--- Tests use a controllable clock (a local `now` variable mutated between
--- method calls) to verify consume-once, expiry, and window-boundary logic.
local tagger = require("provenance.recorder.events.explanation_tags")

describe("ExplanationTagger", function()
  it("no mark → consume() returns nil", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    assert.is_nil(t.consume())
  end)

  it("mark_formatter at now=0, consume at now=0 → 'formatter'", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_formatter()
    local result = t.consume()
    assert.equals("formatter", result)
  end)

  it("within window: mark at 0, now=1999, consume → 'formatter' (1999 < 2000)", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_formatter()
    now = 1999
    local result = t.consume()
    assert.equals("formatter", result)
  end)

  it("at window boundary: mark at 0, now=2000, consume → nil (2000 >= 2000, expired)", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_formatter()
    now = 2000
    local result = t.consume()
    assert.is_nil(result)
  end)

  it("expired path clears slot: after expiry, second consume → nil", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_formatter()
    now = 2000
    local first = t.consume()
    assert.is_nil(first)
    -- Slot was cleared, second consume should also be nil
    local second = t.consume()
    assert.is_nil(second)
  end)

  it("consume-once: mark, consume → kind, second consume (same now) → nil", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_formatter()
    local first = t.consume()
    assert.equals("formatter", first)
    -- Slot was cleared, second consume should be nil
    local second = t.consume()
    assert.is_nil(second)
  end)

  it("latest wins: mark_formatter then mark_git → consume → 'git'", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_formatter()
    t.mark_git()
    local result = t.consume()
    assert.equals("git", result)
  end)

  it("mark_git → consume → 'git'", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_git()
    local result = t.consume()
    assert.equals("git", result)
  end)

  it("expired-then-new-mark: mark at 0, advance to 2000 (consume→nil, expired+cleared), mark_formatter at 2000, consume at 2000 → 'formatter'", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    t.mark_formatter()
    now = 2000
    local expired = t.consume()
    assert.is_nil(expired)
    -- Slot was cleared; now mark a new one at the current time
    t.mark_formatter()
    local fresh = t.consume()
    assert.equals("formatter", fresh)
  end)

  it("custom window_ms=500: mark at now=0, consume at now=100 → 'formatter' (within window)", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end, window_ms = 500 })
    t.mark_formatter()
    now = 100
    local within = t.consume()
    assert.equals("formatter", within)
  end)

  it("custom window_ms=500: mark at now=0, consume at now=500 → nil (at boundary)", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end, window_ms = 500 })
    t.mark_formatter()
    now = 500
    local expired = t.consume()
    assert.is_nil(expired)
  end)

  it("window_ms defaults to 2000 when nil: mark at now=0, consume at now=1999 → 'formatter'", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    -- Don't pass window_ms; should default to 2000
    t.mark_formatter()
    now = 1999
    local within = t.consume()
    assert.equals("formatter", within)
  end)

  it("window_ms defaults to 2000 when nil: mark at now=0, consume at now=2000 → nil", function()
    local now = 0
    local t = tagger.new({ get_now = function() return now end })
    -- Don't pass window_ms; should default to 2000
    t.mark_formatter()
    now = 2000
    local expired = t.consume()
    assert.is_nil(expired)
  end)

  it("two independent instances do not share state", function()
    local now = 0
    local t1 = tagger.new({ get_now = function() return now end })
    local t2 = tagger.new({ get_now = function() return now end })
    t1.mark_formatter()
    local r1 = t1.consume()
    assert.equals("formatter", r1)
    -- t2 should still have nil
    local r2 = t2.consume()
    assert.is_nil(r2)
  end)
end)
