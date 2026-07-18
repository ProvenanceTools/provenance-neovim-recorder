--- Ordered async checkpoint scheduler (Plan 8, Task 2).
---
--- When the checkpoint cadence fires (every 100 entries), the caller signs a
--- `seq -> hash` checkpoint (ed25519) and persists it to the `.slog.meta`.
--- Signing is expensive and must NEVER happen inline on the `on_lines` hot
--- path (CLAUDE.md: "the per-keystroke path only hashes... never move a
--- signing operation into the edit firehose"). This module defers it: there
--- is no Lua threading, so "async" means deferred to the next turn of the
--- event loop via `vim.schedule` — processing itself stays sequential, in
--- FIFO order matching the order `schedule()` was called.
---
--- `sign` and `persist` are injected so the pure ordering/deferral logic is
--- testable without a real ed25519 signer or real file I/O (mirrors
--- heartbeat.lua / paste_reconciler.lua's injected-clock idiom).

local M = {}

--- new(opts) -> scheduler
--- @param opts table {
---   sign: function(seq, hash) -> cp        -- e.g. core.checkpoint.sign(seq, hash, privkey)
---   persist: function(cp)                  -- e.g. meta_writer.append_checkpoint(cp)
---   on_error?: function(err)                -- called on a sign/persist failure; never thrown
--- }
--- @return table { schedule = function(seq, hash), drain = function() }
function M.new(opts)
  opts = opts or {}

  local sign = opts.sign
  local persist = opts.persist
  local on_error = opts.on_error

  -- Ordered FIFO queue of {seq, hash}. Consumed head-first so checkpoints
  -- are signed/persisted in the exact order schedule() was called, matching
  -- the increasing seq order the caller schedules them in.
  local queue = {}
  local queue_head = 1
  local queue_tail = 0

  -- `processing` guards process_all() against re-entrancy: a vim.schedule
  -- flush and a drain() may race (schedule() fires a deferred flush, then
  -- the caller calls drain() before the event loop gets to it). Only one
  -- of the two actually walks the queue; the other finds it already empty
  -- and returns immediately. This is what prevents double-processing.
  local processing = false
  -- `flush_scheduled` avoids queuing more than one vim.schedule callback
  -- while one is already pending.
  local flush_scheduled = false

  --- Process every item currently in the queue, in order, to completion.
  --- Safe to call from both the deferred vim.schedule callback and a
  --- synchronous drain() — the `processing` guard makes concurrent/
  --- re-entrant calls a no-op, and both paths pull from the same shared
  --- queue, so nothing is processed twice.
  local function process_all()
    if processing then
      return
    end
    processing = true

    while queue_head <= queue_tail do
      local item = queue[queue_head]
      queue[queue_head] = nil
      queue_head = queue_head + 1

      local ok_s, cp_or_err = pcall(sign, item.seq, item.hash)
      if not ok_s then
        if on_error then
          pcall(on_error, cp_or_err)
        end
        goto continue
      end

      local ok_p, err = pcall(persist, cp_or_err)
      if not ok_p then
        if on_error then
          pcall(on_error, err)
        end
      end

      ::continue::
    end

    -- Queue is empty again; reset indices so it doesn't grow unbounded.
    queue_head = 1
    queue_tail = 0

    flush_scheduled = false
    processing = false
  end

  local scheduler = {}

  --- schedule(seq, hash): NON-BLOCKING. Appends {seq, hash} to the ordered
  --- queue and ensures the queue will be processed soon on the event loop
  --- (vim.schedule), then returns immediately — sign()/persist() never run
  --- inline here, keeping ed25519 signing off the caller's hot path.
  function scheduler.schedule(seq, hash)
    queue_tail = queue_tail + 1
    queue[queue_tail] = { seq = seq, hash = hash }

    if not flush_scheduled then
      flush_scheduled = true
      vim.schedule(function()
        process_all()
      end)
    end
  end

  --- drain(): SYNCHRONOUSLY process all currently-queued items to
  --- completion right now (sign+persist each, in order). Used by
  --- session.stop to guarantee every pending checkpoint is persisted
  --- before the meta file closes. No-op on an empty queue. If a
  --- vim.schedule flush is also pending, it will find the queue already
  --- empty and do nothing (guarded by `processing`).
  function scheduler.drain()
    process_all()
  end

  return scheduler
end

return M
