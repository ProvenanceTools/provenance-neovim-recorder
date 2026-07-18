--- DiskFullHandler — handles ENOSPC and similar write errors.
---
--- Recorder PRD disk-full row: "Surface a notification; switch to a tiny
--- in-memory ring buffer for critical events only; emit `recorder.degraded`
--- event."
---
--- Port of the monorepo's packages/recorder/src/failure/disk-full-handler.ts.
---
--- Design:
--- - Once degraded, only CRITICAL_KINDS entries are kept (ring buffer, fixed
---   capacity, FIFO eviction of the oldest entry when full).
--- - handle_write_error is idempotent: the first error triggers the
---   transition (notify + on_degraded, each exactly once); subsequent calls
---   are no-ops. v1: any write error is treated as disk-full.
--- - Pure: no Neovim editor API. `notify` and `on_degraded` are injected
---   callbacks; in production notify wraps vim.notify at error level. Never
---   throws.

local M = {}

--- Event kinds retained in degraded mode. All others are dropped.
--- @type table<string, boolean>
M.CRITICAL_KINDS = {
  ["session.start"] = true,
  ["session.end"] = true,
  ["fs.external_change"] = true,
  ["chain.broken"] = true,
  ["recorder.degraded"] = true,
  ["recorder.recovered_from_corruption"] = true,
}

local DEFAULT_RING_CAPACITY = 256

local DEGRADED_MESSAGE = "Disk full — Provenance recording is degraded; only critical events "
  .. "are being retained. Free disk space and restart the session to resume full recording."

--- Create a new DiskFullHandler instance.
--- @param opts table { ring_capacity?: number, on_degraded: function(data), notify: function(message) }
--- @return table Instance with handle_write_error(), enqueue(), is_degraded(), ring_snapshot()
function M.new(opts)
  opts = opts or {}

  local ring_capacity = opts.ring_capacity or DEFAULT_RING_CAPACITY
  local on_degraded = opts.on_degraded
  local notify = opts.notify

  -- Private state, captured in closure.
  local degraded = false
  local ring = {}

  local instance = {}

  --- True if we've transitioned into degraded mode.
  --- @return boolean
  function instance.is_degraded()
    return degraded
  end

  --- Called by the writer's error hook. Triggers degraded mode on first call;
  --- subsequent calls are no-ops (idempotent). Never throws.
  --- @param _err any The write error (unused in v1 — any error is disk-full).
  function instance.handle_write_error(_err)
    if degraded then
      -- Already in degraded mode — idempotent no-op.
      return
    end

    degraded = true

    if notify then
      notify(DEGRADED_MESSAGE)
    end

    if on_degraded then
      on_degraded({ reason = "disk_full" })
    end
  end

  --- Decide whether to retain `entry` in the critical ring while degraded.
  --- Not degraded -> false (normal writer path handles it).
  --- Degraded + critical kind -> push into the ring (FIFO evict oldest at
  --- capacity), return true.
  --- Degraded + non-critical kind -> false (dropped).
  --- @param entry table Envelope-shaped entry with a `kind` field.
  --- @return boolean retained
  function instance.enqueue(entry)
    if not degraded then
      return false
    end

    local kind = entry and entry.kind or nil
    if not kind or not M.CRITICAL_KINDS[kind] then
      return false
    end

    if #ring >= ring_capacity then
      table.remove(ring, 1)
    end

    table.insert(ring, entry)
    return true
  end

  --- Return a copy of the current ring buffer contents. Mutating the
  --- returned list does not affect internal state.
  --- @return table list Copy of the ring, oldest first.
  function instance.ring_snapshot()
    local copy = {}
    for i = 1, #ring do
      copy[i] = ring[i]
    end
    return copy
  end

  return instance
end

return M
