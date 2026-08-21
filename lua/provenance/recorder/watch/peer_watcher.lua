--- peer_watcher.lua — PEER WITNESSING, write side (program spec §7 mechanism 2,
--- collaboration spec §5.5, Tier 4.1).
---
--- In a shared repository a `git pull` drops a partner's `.slog` into
--- `.provenance/`. This module notices, hashes it, reads its chain tip, and
--- writes what it saw into **this** recorder's own signed chain as a
--- `peer.observed` entry. Deleting a partner's log then leaves your own chain
--- testifying that it existed, and hiding that means destroying both chains —
--- which yields a submission with no provenance at all, the loudest possible
--- signal.
---
--- The reader half is `core/peer_observed.lua` (the narrowing, ported from
--- log-core) and the monorepo's `analysis-core/witness/reconcile-witnesses.ts`
--- (the five verdicts). The writer contract, and the seven corrections the
--- first implementation surfaced, are pinned in the monorepo's
--- `docs/superpowers/specs/2026-08-19-program-decision-log.md`. Every numbered
--- rule below is one of its items.
---
--- ===========================================================================
--- 1. ONE WATCHER ON THE DIRECTORY, NOT ONE PER FILE
--- ===========================================================================
---
--- A partner's filename is not knowable in advance — it is a uuid minted on
--- their machine — so a per-file watcher is not even expressible here. One
--- watcher on `.provenance/` is also the only shape that sees a file APPEAR,
--- which is the whole point. It is distinct from the `files_under_review`
--- watchers in `watch/fs_watcher.lua`: those watch the student's own source,
--- this watches provenance artifacts.
---
--- ### DIVERGENCE FROM provcode, DELIBERATE AND FLAGGED
---
--- The drain ALSO lists `.provenance/` itself (`list_dir`, at the top of
--- `drain`, which is I/O in the drain and not on the callback). Two reasons,
--- and the first is a gap in the contract rather than a Neovim quirk:
---
---   a. A file that was ALREADY THERE when the session started fires no create
---      and no change event, so a watcher-only implementation never witnesses
---      it. `git pull` and then open the editor is the ordinary order of
---      events, and provcode's `createFileSystemWatcher` does not report
---      pre-existing entries either — so the corrected contract still misses
---      the commonest case it exists for. Listing the directory closes it.
---   b. `uv.new_fs_event` on a directory is the least reliable watcher libuv
---      offers, and `.provenance/` is written by git checkouts and atomic
---      rename-into-place. `watch/fs_watcher.lua` chose `fs_poll` over
---      `fs_event` for exactly this reason.
---
--- This ADDS observations; it can never suppress one, and it cannot change the
--- bytes of any payload. The rate limit is unaffected because it is structural
--- (a SET, plus rule "unchanged says nothing new"), not a timer.
---
--- ===========================================================================
--- 2. CALLBACKS ENQUEUE A NAME AND RETURN
--- ===========================================================================
---
--- No I/O, no hashing, no parsing, and no `vim` API call on the callback. The
--- recorder's handler budget is <1 ms p99 (PRD §4.7) and hashing a partner's
--- multi-megabyte log on a watcher callback would blow it on the one path a
--- student notices. A callback here is two string comparisons and a table
--- assignment.
---
--- ===========================================================================
--- 3. THE DRAIN RUNS ON THE CHECKPOINT CADENCE
--- ===========================================================================
---
--- Same cadence, and the same serialized chain, as the rolling seal: every
--- `checkpoint_interval` entries, plus once at `stop()` so a pull that landed
--- after the last checkpoint is still witnessed. No timer — the contract's "or
--- a timer, whichever is later" reads backwards, since running both gives
--- whichever is SOONER. Checkpoint + stop means a long-idle session delays
--- witnessing but never loses it, because stop always drains.
---
--- Because the queue is a SET of filenames, a file touched fifty times between
--- two drains yields at most one observation — the rate limit is structural
--- rather than a timer.
---
--- ===========================================================================
--- 4. THIS RECORDER'S OWN FILES ARE EXCLUDED BY PATH
--- ===========================================================================
---
--- A chain cannot corroborate itself. `reconcileWitnesses` excludes a
--- self-witness anyway (`reason: 'self_witness'`), but a recorder must not
--- produce one: an excluded witness is noise in a staff-facing count, and
--- relying on the reader to clean up after the writer is how the two halves
--- drift.
---
--- ===========================================================================
--- 5. A FOREIGN FILE IS NEVER TOUCHED
--- ===========================================================================
---
--- Read and hash is the entire interaction. This module never renames,
--- rewrites, moves, truncates or deletes anything, and it holds NO WRITE-CAPABLE
--- HANDLE: it is constructed with `read_file` and `list_dir` and nothing else,
--- so there is no seam through which a write could be made even by mistake.
--- `state = "unparseable"` is the complete response to a log that cannot be
--- read.
---
--- That is not a stylistic preference. Decision-log bug 2 was a startup
--- recovery that QUARANTINED — renamed — a partner's log with no ownership
--- check, which in a shared repo destroys the victim's evidence and makes git
--- blame them for it, and hands an attacker a way to delete a partner's log by
--- corrupting one byte of it. Watching a directory full of other students'
--- evidence is the second place that mistake could be made. It is not made
--- here. (This port's own `startup/chain_recovery.lua` quarantines only files
--- it has established are this session's own.)
---
--- ===========================================================================
--- 6. NULLS ARE EMITTED EXPLICITLY, NEVER OMITTED
--- ===========================================================================
---
--- `session_id` / `seq_high` / `last_hash` are all-null together or
--- all-non-null together, and they are ALWAYS PRESENT as keys. An omitted key
--- and a `null` value canonicalize differently and therefore chain to different
--- hashes. `events/peer_payload.lua` owns that; this module hands it a tip that
--- is complete or `unread_tip()`, never a half.
---
--- ===========================================================================
--- 7. `seq_high = 0` IS A REAL VALUE
--- ===========================================================================
---
--- A foreign log holding only its `session.start` has `seq_high == 0`. Every
--- comparison here is against `nil` explicitly; a truthiness check would turn
--- the shortest honest witness into a malformed one.
---
--- ===========================================================================
--- 9. `state` IS DESCRIPTIVE, NEVER A VERDICT
--- ===========================================================================
---
--- `disappeared` is NOT misconduct — a `git checkout` of a branch without the
--- partner's `.slog`, or a `git stash`, removes it from the working tree — and
--- it carries the LAST state seen, which is exactly what makes the observation
--- evidentiary. Nothing here scores, flags or ranks anything, and nothing it
--- emits names a person: a witness names a FILE and a CHAIN POSITION.
---
--- ===========================================================================
--- WHY THE DRAIN IS SYNCHRONOUS, AND WHY THAT IS THE SAFETY PROPERTY
--- ===========================================================================
---
--- `emit` is `session_host.emit`, which reads `prev_hash`, chains, and advances
--- `seq` with nothing in between. This port is race-free only because nothing
--- yields across that read-and-advance. A watcher ADDS AN EMITTER, so it is the
--- most likely place to reintroduce the interleaving that manufactures
--- `chain_integrity` and `seq_gaps` findings against innocent students.
---
--- The drain is therefore split in two, and the split is the whole design:
---
---   PHASE 1 — every read, every hash, every parse, for every queued file.
---             Collects payloads. Emits nothing.
---   PHASE 2 — a straight-line loop of `emit` calls with no I/O, no
---             `vim.schedule`, no `vim.wait`, no coroutine yield, and no
---             pcall-per-emit boundary that could reorder anything.
---
--- Adding an `await`-shaped step (a `vim.schedule`, a `uv` async callback, a
--- `vim.wait`) to phase 2 — or moving a read into it — reintroduces exactly the
--- race provcode and provjet had to engineer serializing queues around. Pinned
--- by `tests/recorder/watch/peer_watcher_spec.lua`'s interleaving cases and by
--- `tests/recorder/session/recording_session_peer_spec.lua`.
---
--- ===========================================================================
--- FAILURE IS ALWAYS SILENT DEGRADATION
--- ===========================================================================
---
--- Recording matters more than witnessing. Every read error, parse failure and
--- unexpected exception ends as "no observation for that file this round". The
--- drain never raises and can never stall a session.
local sha256 = require("provenance.core.sha256")
local ndjson = require("provenance.core.ndjson")
local peer_observed = require("provenance.core.peer_observed")
local peer_payload = require("provenance.recorder.events.peer_payload")

local M = {}

local uv = vim.uv or vim.loop

--- Only `.slog` files are witnessed.
---
--- `.slog.meta` carries the session key and the checkpoints, not the chain a
--- witness commits to, and the payload's `session_id` / `seq_high` /
--- `last_hash` are BY DEFINITION reads of a `.slog`. `manifest-<id>.json` /
--- `.sig` are the rolling seal, which the loader already reconciles against the
--- logs present.
---
--- Note this is false for `foo.slog.meta`, which is the intent.
--- @param basename string
--- @return boolean
function M.is_witnessable_log_name(basename)
  return type(basename) == "string" and #basename > 5 and basename:sub(-5) == ".slog"
end

--- What a foreign log's chain says about itself: its logical session id, its
--- highest `seq`, and the `hash` at that `seq`.
---
--- ALL THREE OR NONE (rule 6, and the reader's `partially_parsed` rejection). A
--- log that parses but carries no `session.start`, or whose `session_id` is not
--- a non-empty string, cannot be named — so the honest answer is that the chain
--- was not read, which routes to `state = "unparseable"` (correction 5).
---
--- `seq` is compared with `>` against an explicit `nil`, never truthiness: seq
--- 0 is a real seq and is the whole of the shortest honest witness.
---
--- Exported so the unit tests can drive REAL recorder-produced logs through it
--- rather than hand-built ones.
--- @param text string
--- @return table tip  from peer_payload.chain_tip / unread_tip
function M.read_foreign_chain_tip(text)
  local parsed = ndjson.parse_entries(text)
  if not parsed.ok or #parsed.value == 0 then
    return peer_payload.unread_tip()
  end

  local session_id, seq_high, last_hash = nil, nil, nil
  for _, entry in ipairs(parsed.value) do
    if entry.kind == "session.start" then
      local id = type(entry.data) == "table" and entry.data.session_id or nil
      if type(id) == "string" and #id > 0 then
        session_id = id
      end
    end
    if seq_high == nil or entry.seq > seq_high then
      seq_high = entry.seq
      last_hash = entry.hash
    end
  end

  -- chain_tip is itself all-or-nothing, so a missing session.start collapses
  -- the whole tip rather than producing the half-witness the reader rejects.
  return peer_payload.chain_tip(session_id, seq_high, last_hash)
end

--- The state this observation describes, given the previous one.
---
--- CORRECTION 1. The five states do not partition reality: a rewrite that
--- leaves the length UNCHANGED is neither `grew` nor `shrank`. It is reported
--- as `grew`, with `bytes` emitted alongside so a reader can see the length did
--- not change — whereas `shrank` is the state the vectors describe as "catches
--- a truncation", and reaching for it on a same-length rewrite would lean a
--- DESCRIPTIVE field toward accusation. provcode made this choice; this port
--- makes the same one, because three recorders describing one event three ways
--- is precisely what the shared vectors exist to prevent.
---
--- @param previous table|nil
--- @param bytes number
--- @return string
local function state_for(previous, bytes)
  if previous == nil or not previous.present then
    return "appeared"
  end
  if bytes < previous.bytes then
    return "shrank"
  end
  return "grew"
end

--- Default `read_file` seam: the file's exact bytes, or why not.
---
--- `gone` is ENOENT / ENOTDIR only — an actual absence, which is a fact about
--- the FILE. Everything else (EACCES, EIO, EISDIR, a mid-write share
--- violation) is `unreadable`: a fact about THIS MACHINE. CORRECTION 4 — only
--- `gone` may reach `disappeared`, because putting a claim about a partner's
--- artifact into a signed chain on the strength of a local permission error is
--- manufacturing evidence.
--- @param abs_path string
--- @return table {ok=true, bytes=string} | {ok=false, reason="gone"|"unreadable"}
local function default_read_file(abs_path)
  local fd, _, errname = uv.fs_open(abs_path, "r", 438) -- 438 = 0o666
  if not fd then
    local gone = errname == "ENOENT" or errname == "ENOTDIR"
    return { ok = false, reason = gone and "gone" or "unreadable" }
  end
  local ok, bytes = pcall(function()
    local st = uv.fs_fstat(fd)
    if not st then
      return nil
    end
    if st.size == 0 then
      return ""
    end
    return uv.fs_read(fd, st.size, 0)
  end)
  pcall(uv.fs_close, fd)
  if not ok or type(bytes) ~= "string" then
    return { ok = false, reason = "unreadable" }
  end
  return { ok = true, bytes = bytes }
end

--- Default `list_dir` seam: the basenames directly inside `dir`.
---
--- Read-only, and total: an unreadable directory yields an empty list rather
--- than an error, because witnessing degrades and recording does not.
--- @param dir string
--- @return string[]
local function default_list_dir(dir)
  local names = {}
  local ok, handle = pcall(uv.fs_scandir, dir)
  if not ok or not handle then
    return names
  end
  while true do
    local ok2, name = pcall(uv.fs_scandir_next, handle)
    if not ok2 or name == nil then
      break
    end
    names[#names + 1] = name
  end
  return names
end

--- Default `create_watcher` seam: ONE `uv.new_fs_event` on `.provenance/`.
---
--- Returns a handle with `dispose()`, or nil when a watcher cannot be created —
--- which costs witnessing PROMPTNESS only, never witnessing itself, because the
--- drain lists the directory anyway (see the divergence note in the module
--- docstring).
--- @param dir string
--- @param on_name function(basename: string)
--- @return table|nil
local function default_create_watcher(dir, on_name)
  local ev = uv.new_fs_event()
  if not ev then
    return nil
  end
  local started = pcall(function()
    return ev:start(dir, {}, function(err, filename)
      -- RULE 2: this is the whole callback. No I/O, no hashing, no parsing,
      -- no `vim` API call — a nil check and a function call that does a table
      -- assignment.
      if err == nil and type(filename) == "string" then
        on_name(filename)
      end
    end)
  end)
  if not started then
    pcall(function()
      ev:close()
    end)
    return nil
  end
  return {
    dispose = function()
      pcall(function()
        ev:stop()
        ev:close()
      end)
    end,
  }
end

--- start(opts) -> handle
---
--- @param opts table {
---   provenance_dir: string          -- absolute path of THIS session's .provenance/
---   is_own_file: function(basename) -> boolean  -- rule 4; supplied by the
---     caller because only the session knows its own `.slog` filename uuid,
---     which is minted independently of the LOGICAL session id (the two id
---     spaces decision-log bugs 10 and 12 were both about)
---   emit: function(kind, data)      -- session_host.emit. MUST be synchronous.
---   read_file: function|nil         -- injectable; default reads via vim.uv
---   list_dir: function|nil          -- injectable; default scandir
---   create_watcher: function(dir, on_name) -> handle|nil  -- injectable;
---     default is one uv.new_fs_event. Pass a function returning nil to run
---     drain-scan-only (what most unit tests want).
---   on_debug: function(msg)|nil     -- optional diagnostic sink
--- }
--- @return table handle {
---   drain(): synchronous; never raises,
---   dispose(): idempotent,
---   _enqueue(basename): the watcher callback, exposed for tests,
---   _last_seen(): a copy of the per-file memory, for tests
--- }
function M.start(opts)
  opts = opts or {}

  local provenance_dir = opts.provenance_dir
  local is_own_file = opts.is_own_file or function()
    return false
  end
  local emit = opts.emit
  local read_file = opts.read_file or default_read_file
  local list_dir = opts.list_dir or default_list_dir
  local create_watcher = opts.create_watcher or default_create_watcher
  local on_debug = opts.on_debug

  local function debug_log(msg)
    if on_debug then
      pcall(on_debug, msg)
    elseif vim.g.provenance_debug then
      pcall(vim.notify, "Provenance: peer watcher: " .. msg, vim.log.levels.DEBUG)
    end
  end

  --- Basenames seen since the last drain. A SET, which IS the rate limit: at
  --- most one observation per file per drain no matter how many events arrived.
  local queued = {}
  --- The last observation this session made of each foreign file:
  --- { sha256, bytes, tip, present }. `present` goes false once a
  --- `disappeared` has been emitted, so it is emitted exactly once.
  local last_seen = {}

  local disposed = false
  local draining = false
  local watcher = nil

  --- RULE 2: the whole of the watcher callback.
  local function enqueue(name)
    if disposed then
      return
    end
    if not M.is_witnessable_log_name(name) then
      return
    end
    if is_own_file(name) then
      return -- rule 4: never witness ourselves
    end
    queued[name] = true
  end

  if type(create_watcher) == "function" then
    local ok, w = pcall(create_watcher, provenance_dir, enqueue)
    if ok and type(w) == "table" then
      watcher = w
    elseif not ok then
      -- A watcher that cannot be created costs promptness, never recording.
      debug_log("failed to watch .provenance/: " .. tostring(w))
    end
  end

  --- Observe ONE queued file. Returns the payload to emit, or nil when there is
  --- nothing new or nothing honest to say.
  ---
  --- ALL I/O LIVES HERE, and nothing here emits. That split is what keeps the
  --- chain advance atomic — see `drain`.
  local function observe(name)
    local previous = last_seen[name]
    local read = read_file(provenance_dir .. "/" .. name)
    if type(read) ~= "table" then
      return nil
    end

    if not read.ok then
      -- CORRECTION 4: a local read failure is not a fact about a partner's
      -- file. Only an actual absence is.
      if read.reason ~= "gone" then
        return nil
      end
      -- CORRECTION 3: `disappeared` requires a prior observation. "Carries the
      -- last state seen" is unreachable if we never saw it, and a delete for a
      -- never-observed file has no honest digest — inventing one would be
      -- manufacturing evidence.
      if previous == nil or not previous.present then
        return nil
      end

      last_seen[name] = {
        sha256 = previous.sha256,
        bytes = previous.bytes,
        tip = previous.tip,
        present = false,
      }
      return peer_payload.build(
        name,
        previous.sha256,
        previous.bytes,
        previous.tip,
        "disappeared"
      )
    end

    local bytes = read.bytes
    if type(bytes) ~= "string" then
      return nil
    end

    local digest = sha256.hex(bytes)
    local size = #bytes

    -- CORRECTION 2: unchanged bytes say nothing new. Emitting unconditionally
    -- re-witnesses every partner log at every checkpoint, forever. Skipping
    -- also consumes no `seq`: nothing is chained, so the chain stays
    -- contiguous and validation check 4 sees no hole.
    if previous ~= nil and previous.present and previous.sha256 == digest then
      return nil
    end

    local tip_ok, tip = pcall(M.read_foreign_chain_tip, bytes)
    if not tip_ok or type(tip) ~= "table" then
      tip = peer_payload.unread_tip()
    end

    -- CORRECTION 5 + RULE 5: a log whose chain we could not read gets
    -- `unparseable` AND all-null chain fields, and that is the ENTIRE response.
    -- The file is not renamed, not rewritten, not deleted, not quarantined.
    -- Routing an unread chain to any other state would pass the narrowing
    -- while violating its intent.
    local state
    if peer_payload.tip_was_read(tip) then
      state = state_for(previous, size)
    else
      state = "unparseable"
    end

    last_seen[name] = { sha256 = digest, bytes = size, tip = tip, present = true }
    return peer_payload.build(name, digest, size, tip, state)
  end

  --- The set of names to consider this round.
  ---
  --- Union of three sources, so nothing is missed:
  ---   - what the watcher enqueued (a mid-session pull);
  ---   - what is on disk right now (a pull that predates the session — the gap
  ---     a watcher-only implementation has; see the module docstring);
  ---   - what we have seen before and believe present (so a DELETE is noticed
  ---     even when the watcher's delete event is not delivered).
  local function collect_batch()
    local set = {}
    for name in pairs(queued) do
      set[name] = true
    end
    queued = {}

    local ok, names = pcall(list_dir, provenance_dir)
    if ok and type(names) == "table" then
      for _, name in ipairs(names) do
        if M.is_witnessable_log_name(name) and not is_own_file(name) then
          set[name] = true
        end
      end
    end

    for name, seen in pairs(last_seen) do
      if seen.present then
        set[name] = true
      end
    end

    local batch = {}
    for name in pairs(set) do
      batch[#batch + 1] = name
    end
    -- Sorted so a drain of several files emits in a deterministic order: two
    -- runs of the same session over the same directory must chain identically.
    table.sort(batch)
    return batch
  end

  local handle = {}

  --- Observe every candidate file and emit one `peer.observed` for each that
  --- has something new to say.
  ---
  --- SYNCHRONOUS AND NEVER RAISES. Re-entrancy is refused rather than queued:
  --- a drain that emitted enough entries to trip the checkpoint cadence must
  --- not recurse into itself mid-batch.
  function handle.drain()
    if disposed or draining then
      return
    end
    draining = true

    -- ---------------------------------------------------------------------
    -- PHASE 1 — ALL I/O. Reads, hashes, parses. Emits nothing.
    -- ---------------------------------------------------------------------
    local payloads = {}
    local phase1_ok, phase1_err = pcall(function()
      for _, name in ipairs(collect_batch()) do
        -- Best effort, PER FILE: one unreadable log must not cost the others.
        local ok, payload = pcall(observe, name)
        if not ok then
          debug_log("failed to observe " .. name .. ": " .. tostring(payload))
        elseif payload ~= nil then
          -- Our own reader, on our own writer's output, BEFORE it is chained.
          -- A recorder is the last place a malformed witness can be stopped:
          -- once it is inside a signed log it is permanent, and the analyzer
          -- can only decline it.
          local narrowed = peer_observed.validate(payload.data)
          if narrowed.ok then
            payloads[#payloads + 1] = payload
          else
            debug_log(
              "refusing to emit a malformed witness for "
                .. name
                .. ": "
                .. peer_observed.describe_shape_error(narrowed.error)
            )
          end
        end
      end
    end)
    if not phase1_ok then
      debug_log("drain error: " .. tostring(phase1_err))
    end

    -- ---------------------------------------------------------------------
    -- PHASE 2 — THE CHAIN-ADVANCE SEAM. Every read is above this line.
    --
    -- `emit` is session_host.emit: it reads `prev_hash`, chains, and advances
    -- `seq`/`prev_hash` with no yield inside it, and this loop adds none — so
    -- no other emitter (doc.change, the heartbeat, git wiring) can observe a
    -- half-advanced chain. Introducing a `vim.schedule`, a `vim.wait`, a
    -- `uv` async callback, or a read into this loop reintroduces the
    -- interleaving that manufactures `chain_integrity` and `seq_gaps` findings
    -- against innocent students.
    --
    -- Pinned by the "the chain advance is atomic" cases in
    -- tests/recorder/watch/peer_watcher_spec.lua and
    -- tests/recorder/session/recording_session_peer_spec.lua.
    -- ---------------------------------------------------------------------
    if not disposed and emit ~= nil then
      for _, payload in ipairs(payloads) do
        emit(payload.kind, payload.data)
      end
    end

    draining = false
  end

  --- Idempotent teardown: stops+closes the fs_event so no libuv handle leaks
  --- (a leaked handle keeps headless Neovim from exiting) and makes drain() a
  --- no-op afterwards.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    if watcher then
      pcall(watcher.dispose)
      watcher = nil
    end
    queued = {}
    last_seen = {}
  end

  --- Test seams. `_enqueue` is the watcher callback itself, so a spec can prove
  --- it does no I/O; `_last_seen` is a copy, never the live table.
  handle._enqueue = enqueue
  handle._watching = watcher ~= nil
  function handle._last_seen()
    local copy = {}
    for name, seen in pairs(last_seen) do
      copy[name] = { sha256 = seen.sha256, bytes = seen.bytes, present = seen.present }
    end
    return copy
  end

  return handle
end

return M
