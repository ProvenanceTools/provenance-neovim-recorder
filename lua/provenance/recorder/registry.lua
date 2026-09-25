--- registry.lua — the root -> session map (Plan:
--- 2026-07-20-nested-manifest-discovery). Replaces the single module-level
--- `state`/`controller` pair recorder/init.lua used to own with a table
--- keyed by assignment root, so more than one assignment can record at the
--- same instant, each with its own live recording_controller session.
---
--- Deliberately dumb: this module does not know about discovery, buffers,
--- or autocmds -- it only tracks "which roots currently have a live
--- session" and starts/stops sessions via an injected start_recording seam
--- (production: recording_controller.start; tests: a spy, mirroring
--- init_controller_spec.lua's existing style).
---
--- It also owns the VERIFIED-ROOT CACHE (`reg.load_and_verify`). Activation
--- resolution runs on BufEnter/BufReadPost/BufNewFile, i.e. on every buffer
--- switch, and each resolution used to re-run a pure-Lua ed25519 verification
--- costing ~12 ms on the main loop -- a visible UI hitch inside any activated
--- workspace. The registry is the natural home for that cache: it is already
--- the per-editor-instance "what do we know about this root" map.
local activation = require("provenance.recorder.activation")
local enrollment_policy_gate = require("provenance.recorder.enrollment_policy_gate")
local degraded_notifier = require("provenance.recorder.failure.degraded_notifier")

local M = {}

--- @param opts table {
---   start_recording: function(start_opts) -> controller,
---   notify: function(message)|nil  -- user-facing failure notification; defaults to
---     degraded_notifier.notify (vim.notify at ERROR level), the same channel the
---     disk-full/degraded path uses. A seam so tests can capture it.
--- }
--- @return table registry
function M.new(opts)
  opts = opts or {}
  local start_recording = opts.start_recording
  local notify = opts.notify or degraded_notifier.notify

  -- root -> { manifest, controller, provenance_dir }
  local sessions = {}

  -- root -> true while reg.rotate_session(root) is in flight, guarding
  -- against a re-entrant rotation for the same root (e.g. a second
  -- on_rotate_needed firing before the first replacement session exists).
  local rotating = {}

  -- Verified-root cache: root -> { digest, pubkey_override, result }.
  --
  -- Keyed on the root directory PLUS the manifest's content digest PLUS the
  -- caller's public-key OVERRIDE, so a cached verdict cannot outlive any of the
  -- three inputs that produced it.
  --
  -- The override rather than the resolved key, because since Manifest 2.0 there
  -- is no single resolved key to name up front: activation.evaluate picks the
  -- anchor from the manifest's own `format_version` (2.0 -> root key, 1.x ->
  -- grandfathered legacy course key). Keying on the digest covers that
  -- completely -- the bytes determine the version, the version determines the
  -- anchor -- so a manifest that switches format version between reads has a
  -- different digest and therefore cannot hit a verdict computed under the other
  -- anchor. A `nil` override is a distinct key from any explicit one.
  --
  -- The manifest identity is a sha256 of its bytes, deliberately NOT
  -- mtime+size. This cache short-circuits a security gate, so its key has to be
  -- as hard to forge as the gate itself: mtime and size are both
  -- attacker-controlled (`touch -t`, pad to length), which would let a
  -- "verified" verdict survive the manifest being swapped for a forgery -- the
  -- cache would become the attack. A content digest cannot be spoofed that way,
  -- and it is effectively free: the bytes are read either way, and hashing a few
  -- hundred of them is microseconds against a ~12 ms verification.
  --
  -- Unbounded by root, which is fine: entries are tiny and bounded by the
  -- number of distinct manifest-bearing directories one editor session visits.
  local verified = {}

  local reg = {}

  --- Cached front door to activation.load_and_verify -- same signature, same
  --- return shapes, same semantics, minus the repeated ed25519 cost. Drop-in
  --- for discovery.resolve_from_dir's `load_and_verify` seam.
  ---
  --- Verification still happens on first sight of a root and again after ANY
  --- change to the manifest file's bytes; only a byte-identical re-read is
  --- served from the cache.
  --- @param workspace_dir string
  --- @param pubkey_hex string|nil
  --- @return table  see activation.load_and_verify
  function reg.load_and_verify(workspace_dir, pubkey_hex)
    local read = activation.read_manifest(workspace_dir)
    if read.status ~= "found" then
      -- No bytes means no identity to key on -- and nothing expensive ran.
      return read
    end

    local digest_ok, digest = pcall(vim.fn.sha256, read.text)
    local hit = verified[workspace_dir]
    if digest_ok and hit and hit.digest == digest and hit.pubkey_override == pubkey_hex then
      return hit.result
    end

    local eval_ok, result = pcall(activation.evaluate, read.text, pubkey_hex)
    if not eval_ok then
      return { status = "inactive", reason = "manifest_read_error" }
    end

    -- Only cache when the digest is trustworthy; otherwise re-verify each time.
    if digest_ok then
      verified[workspace_dir] = { digest = digest, pubkey_override = pubkey_hex, result = result }
    end
    return result
  end

  --- Drop every cached verification verdict, forcing the next resolve of each
  --- root to re-verify. Nothing in the plugin needs this today; it exists so no
  --- caller has to reach into the cache table to get a clean slate.
  function reg.clear_verification_cache()
    verified = {}
  end

  --- Aggregate, no-arg (deliberately named to match RecorderState.is_active()
  --- so status.attach(reg) works unmodified): true iff at least one session
  --- is currently registered.
  function reg.is_active()
    return next(sessions) ~= nil
  end

  --- @param root string
  --- @return boolean
  function reg.has_session(root)
    return sessions[root] ~= nil
  end

  --- @param root string
  --- @return table|nil { manifest, controller, provenance_dir }
  function reg.get(root)
    return sessions[root]
  end

  --- Every started session's identity outcome, for `status.lua` and the enroll
  --- nudge. A controller that predates the identity wiring (or whose start was
  --- given no identity store) simply contributes nothing -- "we never asked" is
  --- not "they are not enrolled", and neither surface may turn the first into
  --- the second.
  ---
  --- Each outcome is ANNOTATED with `enrollment_required`, resolved from that
  --- session's own manifest (`policy.enrollment.required`, 2026-08-25
  --- professor-facing "don't nag this course's students" flag,
  --- `enrollment_policy_gate.lua`). It is annotated, never filtered out: this
  --- list is the input to `enroll_nudge.is_unenrolled`, whose check is
  --- deliberately ASYMMETRIC -- "did anyone emit an identity" must still see a
  --- waived session's `emitted` outcome, and only the separate "does anyone
  --- still need to enrol" half is restricted to `enrollment_required` ones.
  --- Dropping a waived session's outcome here entirely would break the first
  --- half for a legacy 2.0 holder enrolled in a waived course but not a
  --- requiring one -- see `enroll_nudge.is_unenrolled`'s doc-comment for the
  --- full scenario. Do not reintroduce a filter here.
  --- @return table[]  { kind = "emitted"|"skipped", enrollment_required, ... }
  function reg.identity_outcomes()
    local out = {}
    for _, entry in pairs(sessions) do
      local outcome = entry.controller and entry.controller._identity_outcome
      if type(outcome) == "table" then
        out[#out + 1] = vim.tbl_extend("force", {}, outcome, {
          enrollment_required = enrollment_policy_gate.effective_required(entry.manifest),
        })
      end
    end
    return out
  end

  --- @return table[]  { root, manifest, controller }, sorted by root ascending
  function reg.list()
    local out = {}
    for root, entry in pairs(sessions) do
      out[#out + 1] = { root = root, manifest = entry.manifest, controller = entry.controller }
    end
    table.sort(out, function(a, b)
      return a.root < b.root
    end)
    return out
  end

  --- Idempotent: if `root` already has a live session, returns it unchanged
  --- (does not call start_recording again). Otherwise starts one.
  --- @param root string
  --- @param manifest table
  --- @param extra_opts table|nil  merged into the start_recording opts,
  ---   winning on any key collision with the derived workspace/provenance_dir/manifest
  --- @return table|nil controller, boolean started, string|nil err
  function reg.ensure_session(root, manifest, extra_opts)
    local existing = sessions[root]
    if existing then
      return existing.controller, false
    end

    local provenance_dir = root .. "/.provenance"
    local start_opts = vim.tbl_extend("force", {
      workspace = root,
      provenance_dir = provenance_dir,
      manifest = manifest,
      -- The ended session's own LOGICAL session_id is threaded through rather
      -- than discarded: rotate_session uses it BOTH as the successor's
      -- prev_session_id and as a staleness check. The callback is vim.schedule'd
      -- by recording_session, so a stop_all() + restart can land in between, and
      -- rotating whichever session happens to be live for this root would rotate
      -- an innocent brand-new one — a spurious extra seam, which under the
      -- lossy-seam problem (design §3.3) is a spurious extra flag against the
      -- student.
      on_rotate_needed = function(ended_session_id)
        reg.rotate_session(root, ended_session_id)
      end,
    }, extra_opts or {})

    local ok, controller = pcall(start_recording, start_opts)
    if not ok then
      return nil, false, controller
    end

    sessions[root] = { manifest = manifest, controller = controller, provenance_dir = provenance_dir }
    return controller, true
  end

  --- Rotate the session at `root`: stop it with reason "rotate" (which emits
  --- `session.end` and takes the final rolling seal), then start a replacement
  --- whose `prev_session_id` names the session that just ended.
  ---
  --- Stop-then-start, not the reverse: `doc_wiring.attach` is per-session and the
  --- old session's autocmds are only detached during its stop, so starting first
  --- would record one keystroke into two logs. The replacement's own catch-up pass
  --- re-emits `doc.open` for every loaded buffer, so it gets its own baseline.
  ---
  --- STALENESS GUARD: when `expected_session_id` is given (production always
  --- gives it), the rotation is abandoned unless the live session for `root` is
  --- still the one that asked to rotate. The request is raised from inside
  --- recording_session's entry path and delivered via vim.schedule, so a
  --- `stop_all()` + restart — `:ProvenanceStop` then a BufEnter, a manifest
  --- change, a reload — can land in between. Without the guard that sequence
  --- rotates a brand-new session that never crossed any size threshold, costing
  --- a gratuitous seam, and every seam is a chance to lose an edit and thereby
  --- accuse the student (design §3.3).
  ---
  --- CHAIN RECOVERY IS SKIPPED for the successor: we already know the
  --- predecessor's id, and recovery would read + chain-validate the whole ~40 MiB
  --- predecessor log on the main loop while no wiring is attached. See
  --- recording_session's `skip_chain_recovery` doc.
  ---
  --- FAILURE IS SURFACED, never silent. `ensure_session` reports a failed start
  --- by RETURNING `nil, false, err` — it does not raise — so a pcall around it
  --- stays `ok` and the old code notified nobody while leaving the root with no
  --- session at all. The student would go on typing, unrecorded, with the
  --- statusline indicator simply gone. Both return values are inspected here and
  --- the failure goes out through the same degraded notification this port uses
  --- for the disk-full path (PRD §4.8); `reg.is_active()` is already false for
  --- this root, so the statusline segment clears itself.
  --- @param root string
  --- @param expected_session_id string|nil  the logical session_id of the session that
  ---   requested the rotation; when non-nil and no longer live for `root`, no-op.
  function reg.rotate_session(root, expected_session_id)
    if rotating[root] then
      return
    end
    rotating[root] = true
    local start_err = nil
    local ok, err = pcall(function()
      local entry = sessions[root]
      if entry == nil then
        return
      end
      local ended_id = entry.controller.session_id
      if expected_session_id ~= nil and ended_id ~= expected_session_id then
        -- Not the session that asked: a stop+restart raced the scheduled
        -- callback. The session that wanted to rotate is already gone and sealed.
        return
      end
      pcall(entry.controller.stop, "rotate")
      sessions[root] = nil
      local _, _, e = reg.ensure_session(root, entry.manifest, {
        prev_session_id = ended_id,
        skip_chain_recovery = true,
      })
      start_err = e
    end)
    rotating[root] = nil
    if not ok then
      notify("Provenance: session rotation failed (recording has stopped for this assignment): " .. tostring(err))
    elseif start_err ~= nil then
      notify(
        "Provenance: could not restart recording after rotating the log "
          .. "(recording has stopped for this assignment): "
          .. tostring(start_err)
      )
    end
  end

  --- Stop every registered session (pcall-guarded per entry, so one
  --- failing stop() never blocks the others) and clear the registry.
  --- Order-independent by construction (Lua's pairs() order is
  --- unspecified) -- this is deliberate: see paste_intercept.lua's
  --- ref-counted-singleton fix for why teardown order must never matter.
  --- @param reason string|nil
  function reg.stop_all(reason)
    for root, entry in pairs(sessions) do
      pcall(entry.controller.stop, reason)
      sessions[root] = nil
    end
  end

  return reg
end

return M
