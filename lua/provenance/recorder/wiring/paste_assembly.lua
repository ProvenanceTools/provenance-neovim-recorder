--- paste_assembly.lua — Plan 6, Task 6: wires the three paste-detection
--- signals (paste_classifier, the vim.paste intercept, and clipboard content
--- matching, fused by paste_correlator) into doc_wiring's on_lines path via
--- the change-router seam (doc_wiring.lua's `handle.set_change_router`),
--- replacing Plan 4's hardcoded `source = "typed"`.
---
--- Composes, in order:
---   1. paste_correlator.new    — the fusion decision tree (pure).
---   2. paste_intercept.attach  — wraps vim.paste, feeds
---      correlator.on_paste_intercept (signal 2+3).
---   3. doc_wiring_handle.set_change_router(router) — every on_lines delta
---      is routed through correlator.on_doc_change (signal 1 + fusion), and
---      the resulting decision is turned into the emitted {kind, data} event
---      shape (paste / doc.change).
---   4. paste_reconciler.start  — the anomaly watchdog, fed by
---      correlator.counts().
---
--- `handle.dispose()` tears down all three in reverse and unhooks the
--- router, restoring doc_wiring's default source="typed" behavior.
local paste_correlator = require("provenance.recorder.events.paste_correlator")
local paste_intercept = require("provenance.recorder.wiring.paste_intercept")
local paste_reconciler = require("provenance.recorder.events.paste_reconciler")
local doc_events = require("provenance.recorder.events.doc_events")

local M = {}

local function default_get_now()
  return (vim.uv or vim.loop).hrtime() / 1e6
end

--- attach(opts) -> handle
---
--- opts:
---   emit               function(kind, data) -- SessionHost.emit
---   doc_wiring_handle  table                -- the handle returned by
---                        doc_wiring.attach(); must expose set_change_router
---   get_now            function() -> number -- injected clock; default
---                        vim.uv.hrtime()/1e6 (milliseconds)
---   window_ms          number|nil -- passed through to paste_correlator.new
---   interval_ms        number|nil -- passed through to paste_reconciler.start
---   tolerance          number|nil -- passed through to paste_reconciler.start
function M.attach(opts)
  opts = opts or {}

  local emit = opts.emit
  local doc_wiring_handle = opts.doc_wiring_handle
  local get_now = opts.get_now or default_get_now

  local correlator = paste_correlator.new({
    get_now = get_now,
    window_ms = opts.window_ms,
  })

  local intercept = paste_intercept.attach({
    on_intercept = function(text, at)
      correlator.on_paste_intercept(text, at)
    end,
    get_now = get_now,
  })

  --- The router: called once per on_lines delta by doc_wiring. Turns the
  --- correlator's fused decision into the {kind, data} event shape.
  local function router(rel, deltas, range)
    local decision = correlator.on_doc_change(deltas, range, get_now())

    if decision.kind == "paste" then
      local data = {
        path = rel,
        range = decision.range,
        length = decision.payload.length,
        sha256 = decision.payload.sha256,
      }
      -- Copy the optional inline-vs-truncated content fields IF present
      -- (build_paste_payload sets exactly one of content OR
      -- content_head+content_tail; the nil ones simply stay absent).
      data.content = decision.payload.content
      data.content_head = decision.payload.content_head
      data.content_tail = decision.payload.content_tail
      return { kind = "paste", data = data }
    end

    -- decision.kind == "doc.change": reuse the pure transform for shape,
    -- then override source to the correlator's decision ("typed" or
    -- "paste_likely" — this is the seam that replaces Plan 4's hardcoded
    -- "typed").
    local ev = doc_events.transform_doc_change(rel, decision.deltas)
    ev.data.source = decision.source
    return { kind = ev.kind, data = ev.data }
  end

  doc_wiring_handle.set_change_router(router)

  local reconciler = paste_reconciler.start({
    interval_ms = opts.interval_ms,
    tolerance = opts.tolerance,
    emit = emit,
    get_intercepted_count = function()
      return correlator.counts().intercepted
    end,
    get_large_insert_count = function()
      return correlator.counts().large_insert
    end,
  })

  local disposed = false
  local handle = {}

  --- Idempotent: tears down the reconciler timer, restores vim.paste, and
  --- unhooks the change-router from doc_wiring (restoring its default
  --- source="typed" routing). Safe to call more than once.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true

    intercept.dispose()
    reconciler.dispose()
    doc_wiring_handle.set_change_router(nil)
  end

  return handle
end

return M
