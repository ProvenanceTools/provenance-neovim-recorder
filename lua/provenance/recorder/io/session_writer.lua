--- Buffered, append-only `.slog` writer (Plan 4). Sits downstream of
--- SessionHost (`on_entry = writer.append`). `append` must be cheap on the
--- hot path (`on_lines` fires per keystroke): it only serializes via
--- `core.ndjson.serialize_entry` and buffers — no signing, no I/O. Actual
--- disk writes are batched by `core.buffer_policy` and a periodic
--- `vim.uv` timer.
---
--- The `.slog` is append-only: writes go through `fs_open(path, "a")`,
--- never through `atomic_write` (that primitive is reserved for
--- `.slog.meta` / `manifest.json` / `manifest.sig`, which are rewritten
--- wholesale and must never be left half-written).
---
--- On a write failure the buffer is DROPPED, not restored or retried —
--- durability/replay is a later plan's job. `on_error` is called
--- best-effort and the writer never raises out of `flush()`, so a
--- transient disk failure can't crash the editor.
local ndjson = require("provenance.core.ndjson")
local buffer_policy = require("provenance.core.buffer_policy")

local M = {}

local function ensure_parent_dir(path)
  local parent = path:match("(.*)/[^/]*$")
  if parent and parent ~= "" then
    vim.fn.mkdir(parent, "p")
  end
end

--- @param opts table {slog_path, clock, buffer_policy?, on_error?}
--- @return table writer {append, flush, dispose}
function M.open(opts)
  local slog_path = opts.slog_path
  local clock = opts.clock
  local on_error = opts.on_error
  local max_bytes = (opts.buffer_policy and opts.buffer_policy.max_bytes) or buffer_policy.DEFAULT_MAX_BYTES
  local max_interval_ms = (opts.buffer_policy and opts.buffer_policy.max_interval_ms)
    or buffer_policy.DEFAULT_MAX_INTERVAL_MS

  local uv = vim.uv or vim.loop

  local buf = {}
  local buffered_bytes = 0
  local last_flush_ms = clock.now()
  local disposed = false

  local writer = {}

  --- Write all currently buffered lines to disk in order. Never flushes an
  --- empty buffer (no file is created/touched by a no-op flush). Never
  --- raises: any failure is reported via `on_error` and drops the buffer.
  function writer.flush()
    if #buf == 0 then
      return
    end

    local blob = table.concat(buf)

    local function fail(err)
      buf = {}
      buffered_bytes = 0
      last_flush_ms = clock.now()
      if on_error then
        pcall(on_error, err)
      end
    end

    -- vim.fn.mkdir("p") raises (E739) rather than returning falsy when a
    -- path component exists as a non-directory file, so this must be
    -- pcall-guarded like every other step: flush() must never throw.
    local mkdir_ok, mkdir_err = pcall(ensure_parent_dir, slog_path)
    if not mkdir_ok then
      fail(mkdir_err or "session_writer: mkdir failed")
      return
    end

    local fd, open_err = uv.fs_open(slog_path, "a", 420) -- 420 = 0o644
    if not fd then
      fail(open_err or "session_writer: fs_open failed")
      return
    end

    local written, write_err = uv.fs_write(fd, blob)
    if type(written) ~= "number" then
      pcall(uv.fs_close, fd)
      fail(write_err or "session_writer: fs_write failed")
      return
    end

    local closed, close_err = uv.fs_close(fd)
    if not closed then
      fail(close_err or "session_writer: fs_close failed")
      return
    end

    buf = {}
    buffered_bytes = 0
    last_flush_ms = clock.now()
  end

  --- Synchronous, hot-path append: serialize + buffer only. Consults
  --- buffer_policy to decide whether to flush now.
  function writer.append(hashed)
    if disposed then
      error("session_writer: append after dispose")
    end

    local line = ndjson.serialize_entry(hashed)
    buf[#buf + 1] = line
    buffered_bytes = buffered_bytes + #line

    if buffer_policy.should_flush({
      buffered_bytes = buffered_bytes,
      last_flush_ms = last_flush_ms,
      now_ms = clock.now(),
      max_bytes = max_bytes,
      max_interval_ms = max_interval_ms,
    }) then
      writer.flush()
    end
  end

  local timer = uv.new_timer()
  timer:start(max_interval_ms, max_interval_ms, vim.schedule_wrap(function()
    if not disposed then
      pcall(writer.flush)
    end
  end))

  --- Idempotent teardown: stop the timer, flush anything still buffered,
  --- then mark disposed so further appends error.
  function writer.dispose()
    if disposed then
      return
    end
    pcall(function()
      timer:stop()
      timer:close()
    end)
    pcall(writer.flush)
    disposed = true
  end

  return writer
end

return M
