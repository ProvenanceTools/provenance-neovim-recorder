--- RecordingController: the Plan 9 CAPSTONE production entry point. It IS a
--- full-signals recording_session — a thin wrapper that starts
--- recording_session with `enable_signals = true`, so every signal (paste,
--- external-change, terminal/git/snapshot, clock-skew) is composed into one
--- live lifecycle with a single dispose (session.stop).
---
--- WHY A SEPARATE MODULE: recording_session with `enable_signals = false` is
--- the lean core exercised by focused specs (recording_session_spec and the
--- checkpoints/recovery/degraded/lifecycle specs) and the e2e driver — those
--- want to test the core wiring seam without the full signal fan-out.
--- recording_controller is what the plugin actually starts on activation
--- (recorder/init.lua): the same session table (seal/stop/is_degraded/
--- session_id/slog_path/public_key_hex/_signals), with all signals live.
local recording_session = require("provenance.recorder.session.recording_session")

local M = {}

--- start(opts) -> controller
---
--- Identical to recording_session.start(opts) except `enable_signals` is
--- forced true. `opts` is the same shape recording_session.start documents
--- (workspace, provenance_dir, manifest, clock, ...); any `enable_signals`
--- the caller passes is overridden to true.
--- @param opts table  -- see recording_session.start
--- @return table  -- the full-signals recording session (with ._signals populated)
function M.start(opts)
  return recording_session.start(vim.tbl_extend("force", {}, opts or {}, { enable_signals = true }))
end

return M
