--- Buffered, append-only `.slog` writer (Plan 4). `append` is synchronous
--- and hot-path cheap: serialize + buffer only. Actual disk writes are
--- batched by `core.buffer_policy` and a periodic `vim.uv` timer. Real
--- vim.uv against real temp-dir fixtures, per CLAUDE.md's testing bar for
--- editor-seam code; time is injected via `core.clock.fixed` for
--- determinism.
local session_writer = require("provenance.recorder.io.session_writer")
local clock = require("provenance.core.clock")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local ndjson = require("provenance.core.ndjson")

local function make_tempdir()
  local dir = vim.fn.tempname()
  vim.fn.mkdir(dir, "p")
  return dir
end

--- Build a HashedEnvelope chained onto GENESIS, with distinct `data` per
--- seq so entries are individually recognizable in assertions.
local function make_entry(seq, marker)
  return hc.chain_entry(hc.GENESIS_PREV_HASH,
    envelope.new(seq, seq, "2026-01-01T00:00:00.000Z", "doc.open", { path = marker }))
end

local function read_file(path)
  if vim.uv.fs_stat(path) == nil then return nil end
  local lines = vim.fn.readfile(path)
  return table.concat(lines, "\n") .. (#lines > 0 and "\n" or "")
end

describe("session_writer", function()
  local tempdirs = {}
  local writers = {}

  local function new_tempdir()
    local dir = make_tempdir()
    table.insert(tempdirs, dir)
    return dir
  end

  local function track(w)
    table.insert(writers, w)
    return w
  end

  after_each(function()
    for _, w in ipairs(writers) do
      pcall(w.dispose)
    end
    writers = {}
    for _, dir in ipairs(tempdirs) do
      vim.fn.delete(dir, "rf")
    end
    tempdirs = {}
  end)

  it("appended lines land in the .slog in order after flush", function()
    local dir = new_tempdir()
    local slog_path = dir .. "/session.slog"
    local fake_clock = clock.fixed(0, 0)
    local w = track(session_writer.open({ slog_path = slog_path, clock = fake_clock }))

    local e1 = make_entry(0, "one")
    local e2 = make_entry(1, "two")
    local e3 = make_entry(2, "three")
    w.append(e1)
    w.append(e2)
    w.append(e3)
    w.flush()

    local text = read_file(slog_path)
    assert.is_truthy(text)
    local res = ndjson.parse_entries(text)
    assert.is_true(res.ok)
    assert.equals(3, #res.value)
    assert.equals("one", res.value[1].data.path)
    assert.equals("two", res.value[2].data.path)
    assert.equals("three", res.value[3].data.path)
  end)

  it("auto-flushes when buffered_bytes exceeds a tiny max_bytes", function()
    local dir = new_tempdir()
    local slog_path = dir .. "/session.slog"
    local fake_clock = clock.fixed(0, 0)
    local w = track(session_writer.open({
      slog_path = slog_path,
      clock = fake_clock,
      buffer_policy = { max_bytes = 10, max_interval_ms = 60000 },
    }))

    local e1 = make_entry(0, "auto-flush-me")
    w.append(e1) -- serialized line is well over 10 bytes

    local text = read_file(slog_path)
    assert.is_truthy(text)
    assert.is_truthy(text:match("auto%-flush%-me"))
  end)

  it("errors on append after dispose", function()
    local dir = new_tempdir()
    local slog_path = dir .. "/session.slog"
    local fake_clock = clock.fixed(0, 0)
    local w = session_writer.open({ slog_path = slog_path, clock = fake_clock })
    w.dispose()

    local ok = pcall(w.append, make_entry(0, "too-late"))
    assert.is_false(ok)
  end)

  it("invokes on_error and drops the buffer on a forced write failure, without throwing", function()
    local dir = new_tempdir()
    -- Force fs_open/mkdir failure by making a PARENT path component a
    -- regular file rather than a directory.
    local blocker = dir .. "/blocker"
    vim.fn.writefile({ "not a directory" }, blocker)
    local slog_path = blocker .. "/session.slog"

    local fake_clock = clock.fixed(0, 0)
    local errors = {}
    local w = track(session_writer.open({
      slog_path = slog_path,
      clock = fake_clock,
      on_error = function(err) table.insert(errors, err) end,
    }))

    local ok = pcall(w.append, make_entry(0, "will-fail"))
    assert.is_true(ok)
    local flush_ok = pcall(w.flush)
    assert.is_true(flush_ok)

    assert.equals(1, #errors)
    assert.is_truthy(errors[1])

    -- The dropped line must not resurface: appending+flushing again against
    -- the same broken path only ever reports one more failure, never a
    -- write that somehow contains the first entry.
    assert.is_true(pcall(w.append, make_entry(1, "also-fails")))
    assert.is_true(pcall(w.flush))
    assert.equals(2, #errors)
  end)

  it("flushes buffered entries on dispose even without an explicit flush call", function()
    local dir = new_tempdir()
    local slog_path = dir .. "/session.slog"
    local fake_clock = clock.fixed(0, 0)
    local w = session_writer.open({
      slog_path = slog_path,
      clock = fake_clock,
      buffer_policy = { max_bytes = 1024 * 1024, max_interval_ms = 60000 },
    })

    w.append(make_entry(0, "flushed-on-dispose"))
    -- Below both thresholds: nothing written yet.
    assert.is_nil(read_file(slog_path))

    w.dispose()

    local text = read_file(slog_path)
    assert.is_truthy(text)
    assert.is_truthy(text:match("flushed%-on%-dispose"))
  end)

  it("dispose is idempotent", function()
    local dir = new_tempdir()
    local slog_path = dir .. "/session.slog"
    local fake_clock = clock.fixed(0, 0)
    local w = session_writer.open({ slog_path = slog_path, clock = fake_clock })

    w.dispose()
    local ok = pcall(w.dispose)
    assert.is_true(ok)
  end)
end)
