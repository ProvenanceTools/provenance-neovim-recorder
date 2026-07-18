--- Pure decision logic for when SessionWriter should flush its buffer to
--- disk (Plan 4 Global Constraints). Never flush an empty buffer; flush
--- when buffered_bytes crosses max_bytes OR the interval since last_flush_ms
--- crosses max_interval_ms.
local buffer_policy = require("provenance.core.buffer_policy")

describe("buffer_policy.should_flush", function()
  it("never flushes an empty buffer, even if the interval has elapsed", function()
    local flush = buffer_policy.should_flush({
      buffered_bytes = 0,
      last_flush_ms = 0,
      now_ms = 10000,
      max_bytes = 100,
      max_interval_ms = 1000,
    })
    assert.is_false(flush)
  end)

  it("flushes when buffered_bytes is at max_bytes", function()
    local flush = buffer_policy.should_flush({
      buffered_bytes = 100,
      last_flush_ms = 0,
      now_ms = 0,
      max_bytes = 100,
      max_interval_ms = 1000,
    })
    assert.is_true(flush)
  end)

  it("flushes when buffered_bytes is over max_bytes", function()
    local flush = buffer_policy.should_flush({
      buffered_bytes = 150,
      last_flush_ms = 0,
      now_ms = 0,
      max_bytes = 100,
      max_interval_ms = 1000,
    })
    assert.is_true(flush)
  end)

  it("flushes when the interval since last_flush_ms is at max_interval_ms", function()
    local flush = buffer_policy.should_flush({
      buffered_bytes = 1,
      last_flush_ms = 0,
      now_ms = 1000,
      max_bytes = 100,
      max_interval_ms = 1000,
    })
    assert.is_true(flush)
  end)

  it("flushes when the interval since last_flush_ms is over max_interval_ms", function()
    local flush = buffer_policy.should_flush({
      buffered_bytes = 1,
      last_flush_ms = 0,
      now_ms = 5000,
      max_bytes = 100,
      max_interval_ms = 1000,
    })
    assert.is_true(flush)
  end)

  it("does not flush a non-empty buffer under both thresholds", function()
    local flush = buffer_policy.should_flush({
      buffered_bytes = 1,
      last_flush_ms = 0,
      now_ms = 500,
      max_bytes = 100,
      max_interval_ms = 1000,
    })
    assert.is_false(flush)
  end)

  it("exposes the default thresholds", function()
    assert.equals(256 * 1024, buffer_policy.DEFAULT_MAX_BYTES)
    assert.equals(1000, buffer_policy.DEFAULT_MAX_INTERVAL_MS)
  end)
end)
