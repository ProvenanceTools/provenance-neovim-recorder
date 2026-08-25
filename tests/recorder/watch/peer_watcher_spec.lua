--- Peer witnessing, write side (program spec §7 mechanism 2, collaboration
--- spec §5.5, Tier 4.1).
---
--- Two things are being defended here and they pull in opposite directions:
---
---   1. A partner's log that was deleted must leave THIS chain testifying that
---      it existed. That argues for witnessing aggressively.
---   2. Nothing this module writes may be capable of accusing an innocent
---      student — not by re-witnessing forever, not by reporting a local
---      permission error as a partner's file vanishing, and above all not by
---      interleaving with another emitter and manufacturing a chain break.
---
--- Every case below is one of those two. The seven CORRECTIONS the first
--- implementation (provcode) surfaced each get a named case, because three
--- recorders describing one event three different ways is exactly what the
--- shared conformance vectors exist to prevent.
local peer_watcher = require("provenance.recorder.watch.peer_watcher")
local peer_observed = require("provenance.core.peer_observed")
local core_json = require("provenance.core.json")
local sha256 = require("provenance.core.sha256")
local session_host = require("provenance.recorder.session.session_host")
local hash_chain = require("provenance.core.hash_chain")

local FOREIGN = "session-7f3a1c22-9b0e-4d51-8a77-2c6e5d0b41af.slog"
local OWN = "session-0000aaaa-0000-0000-0000-000000000000.slog"

--- A fake filesystem: name -> string bytes, or a `{ error = "EACCES" }` marker.
--- Records every path read so a test can prove what was and was not touched,
--- and exposes only read operations, mirroring the real seam.
local function fake_fs(files)
  local fs = { files = files or {}, reads = {}, listed = 0 }

  function fs.read_file(abs)
    fs.reads[#fs.reads + 1] = abs
    local name = abs:match("[^/]+$")
    local entry = fs.files[name]
    if entry == nil then
      return { ok = false, reason = "gone" }
    end
    if type(entry) == "table" then
      return { ok = false, reason = entry.reason or "unreadable" }
    end
    return { ok = true, bytes = entry }
  end

  function fs.list_dir()
    fs.listed = fs.listed + 1
    local names = {}
    for name in pairs(fs.files) do
      names[#names + 1] = name
    end
    table.sort(names)
    return names
  end

  return fs
end

--- A recorder of emitted events, plus the emit function itself.
local function recorder()
  local events = {}
  return events, function(kind, data)
    events[#events + 1] = { kind = kind, data = data }
  end
end

local function start(fs, overrides)
  local o = vim.tbl_extend("force", {
    provenance_dir = "/tmp/ws/.provenance",
    is_own_file = function(name)
      return name == OWN or name == OWN .. ".meta"
    end,
    read_file = fs.read_file,
    list_dir = fs.list_dir,
    -- No real fs_event in unit tests: the drain's own directory listing is the
    -- discovery mechanism under test, and a libuv handle here would leak.
    create_watcher = function()
      return nil
    end,
  }, overrides or {})
  return peer_watcher.start(o)
end

--- A minimal but REAL foreign log: entries built through this port's own
--- envelope + hash chain, so the tip read out of it is read out of the same
--- bytes a recorder would have written.
local function foreign_log(session_id, n_entries)
  local envelope = require("provenance.core.envelope")
  local ndjson = require("provenance.core.ndjson")
  local prev = hash_chain.GENESIS_PREV_HASH
  local lines = {}
  local last
  for seq = 0, n_entries - 1 do
    local kind = seq == 0 and "session.start" or "session.heartbeat"
    local data = seq == 0 and { session_id = session_id } or { focused = true }
    local env = envelope.new(seq, seq * 10, "2026-01-01T00:00:0" .. (seq % 10) .. ".000Z", kind, data)
    local entry = hash_chain.chain_entry(prev, env)
    prev = entry.hash
    last = entry
    lines[#lines + 1] = ndjson.serialize_entry(entry)
  end
  return table.concat(lines), last
end

describe("peer_watcher.is_witnessable_log_name", function()
  it("witnesses only `*.slog`", function()
    assert.is_true(peer_watcher.is_witnessable_log_name("session-abc.slog"))
    -- `.slog.meta` carries the session key and the checkpoints, not the chain a
    -- witness commits to, and the payload's chain fields are BY DEFINITION
    -- reads of a `.slog`.
    assert.is_false(peer_watcher.is_witnessable_log_name("session-abc.slog.meta"))
    -- The rolling seal, which the loader already reconciles against the logs
    -- present.
    assert.is_false(peer_watcher.is_witnessable_log_name("manifest-abc.json"))
    assert.is_false(peer_watcher.is_witnessable_log_name("manifest-abc.sig"))
    assert.is_false(peer_watcher.is_witnessable_log_name("manifest.json"))
    assert.is_false(peer_watcher.is_witnessable_log_name(".slog"))
    assert.is_false(peer_watcher.is_witnessable_log_name("slog"))
    assert.is_false(peer_watcher.is_witnessable_log_name(""))
    assert.is_false(peer_watcher.is_witnessable_log_name(nil))
  end)
end)

describe("peer_watcher.read_foreign_chain_tip", function()
  it("reads a REAL recorder-produced log's id, seq_high and tip hash", function()
    local text, last = foreign_log("4e2d9c10-55af-4b3e-9d21-8f0c7a6b3e55", 5)
    local tip = peer_watcher.read_foreign_chain_tip(text)
    assert.equals("4e2d9c10-55af-4b3e-9d21-8f0c7a6b3e55", tip.session_id)
    assert.equals(4, tip.seq_high)
    assert.equals(last.hash, tip.last_hash)
  end)

  it("`seq_high = 0` is a real tip — a log holding only its session.start", function()
    -- The shortest possible honest witness. A truthiness check on seq_high
    -- turns it into an unparsed one.
    local text, last = foreign_log("s-1", 1)
    local tip = peer_watcher.read_foreign_chain_tip(text)
    assert.equals(0, tip.seq_high)
    assert.equals(last.hash, tip.last_hash)
    assert.equals("s-1", tip.session_id)
  end)

  it("a log with no session.start yields NO tip at all, not a partial one", function()
    -- All three or none. Naming a seq while being unable to name the session is
    -- the half-witness the reader rejects as `partially_parsed`.
    local envelope = require("provenance.core.envelope")
    local ndjson = require("provenance.core.ndjson")
    local env = envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "doc.change", { path = "a.py" })
    local entry = hash_chain.chain_entry(hash_chain.GENESIS_PREV_HASH, env)
    local tip = peer_watcher.read_foreign_chain_tip(ndjson.serialize_entry(entry))
    assert.equals(core_json.NULL, tip.session_id)
    assert.equals(core_json.NULL, tip.seq_high)
    assert.equals(core_json.NULL, tip.last_hash)
  end)

  it("garbage, empty text and a conflict-marked file all yield no tip", function()
    for _, text in ipairs({
      "",
      "not json at all",
      '{"seq":0}\n',
      "<<<<<<< HEAD\n{}\n=======\n{}\n>>>>>>> theirs\n",
    }) do
      local tip = peer_watcher.read_foreign_chain_tip(text)
      assert.equals(core_json.NULL, tip.session_id, vim.inspect(text))
    end
  end)
end)

describe("peer_watcher: the five states", function()
  it("appeared -> grew -> shrank, and every payload our reader accepts", function()
    local a = foreign_log("s-a", 2)
    local fs = fake_fs({ [FOREIGN] = a })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })

    w.drain()
    assert.equals(1, #events)
    assert.equals("peer.observed", events[1].kind)
    assert.equals("appeared", events[1].data.state)
    assert.equals(FOREIGN, events[1].data.file)
    assert.equals(sha256.hex(a), events[1].data.sha256)
    assert.equals(#a, events[1].data.bytes)
    assert.equals("s-a", events[1].data.session_id)

    -- A genuine append: the partner kept recording. Still a valid chain, so the
    -- tip advances and the state is descriptive of the length change only.
    local longer = foreign_log("s-a", 6)
    assert.is_true(#longer > #a)
    fs.files[FOREIGN] = longer
    w.drain()
    assert.equals(2, #events)
    assert.equals("grew", events[2].data.state)
    assert.equals(5, events[2].data.seq_high)

    -- A genuine truncation: append-only logs do not shrink. Still only an
    -- OBSERVATION, and not by itself misconduct.
    local shorter = foreign_log("s-a", 2)
    assert.is_true(#shorter < #longer)
    fs.files[FOREIGN] = shorter
    w.drain()
    assert.equals(3, #events)
    assert.equals("shrank", events[3].data.state)

    for _, e in ipairs(events) do
      assert.is_true(peer_observed.validate(e.data).ok)
    end
    w.dispose()
  end)

  it("CORRECTION 1: a SAME-LENGTH rewrite is `grew`, with bytes alongside", function()
    -- The five states do not partition reality. provcode reports `grew` and
    -- emits `bytes` beside it so a reader can see the length did not change;
    -- `shrank` is described in the vectors as "catches a truncation", and
    -- reaching for it here would lean a DESCRIPTIVE field toward accusation.
    -- This port must make the SAME choice or the three recorders disagree.
    local a = foreign_log("s-a", 3)
    local fs = fake_fs({ [FOREIGN] = a })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w.drain()
    assert.equals("appeared", events[1].data.state)

    -- Same length, different bytes: a rewrite in place, which is neither an
    -- append nor a truncation. Built as a DIFFERENT but equally long valid
    -- chain — a session id of the same width, so every envelope is the same
    -- width — so the file still parses and the state is a real choice between
    -- `grew` and `shrank` rather than a fall-through to `unparseable`.
    local rewritten = foreign_log("s-b", 3)
    assert.equals(#a, #rewritten)
    assert.are_not.equals(a, rewritten)
    fs.files[FOREIGN] = rewritten

    w.drain()
    assert.equals(2, #events)
    assert.equals("grew", events[2].data.state)
    assert.equals(#a, events[2].data.bytes)
    -- ...and the reader can see the length did not change.
    assert.equals(events[1].data.bytes, events[2].data.bytes)
    w.dispose()
  end)

  it("CORRECTION 2: an UNCHANGED file is not re-emitted, at any number of drains", function()
    -- The contract never said. Emitting unconditionally re-witnesses every
    -- partner log at every checkpoint, forever — which for a long session is
    -- thousands of identical entries about somebody else's file.
    local fs = fake_fs({ [FOREIGN] = foreign_log("s-a", 4) })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })

    for _ = 1, 20 do
      w.drain()
    end
    assert.equals(1, #events)

    -- ...and a change after all that silence is still noticed.
    fs.files[FOREIGN] = foreign_log("s-a", 7)
    w.drain()
    assert.equals(2, #events)
    assert.equals("grew", events[2].data.state)
    w.dispose()
  end)

  it("CORRECTION 3: `disappeared` requires a PRIOR observation", function()
    -- "Carries the last state seen" is unreachable if you never saw it, and a
    -- delete for a never-observed file has no honest digest. Inventing one
    -- would be manufacturing evidence about a third party.
    local fs = fake_fs({})
    local events, emit = recorder()
    local w = start(fs, { emit = emit })

    w._enqueue(FOREIGN) -- named by a delete event for a file we never read
    w.drain()
    assert.equals(0, #events)

    -- Now witness it, then delete it: THAT is evidentiary.
    local a = foreign_log("s-a", 3)
    fs.files[FOREIGN] = a
    w.drain()
    assert.equals(1, #events)
    assert.equals("appeared", events[1].data.state)

    fs.files[FOREIGN] = nil
    w.drain()
    assert.equals(2, #events)
    assert.equals("disappeared", events[2].data.state)
    -- The digest and chain fields carry the LAST STATE SEEN, which is what
    -- makes the observation evidentiary at all.
    assert.equals(sha256.hex(a), events[2].data.sha256)
    assert.equals(#a, events[2].data.bytes)
    assert.equals("s-a", events[2].data.session_id)
    assert.equals(events[1].data.last_hash, events[2].data.last_hash)

    -- ...and it is emitted exactly ONCE, not at every subsequent drain.
    for _ = 1, 5 do
      w.drain()
    end
    assert.equals(2, #events)
    w.dispose()
  end)

  it("CORRECTION 4: a LOCAL read failure emits nothing — it is not an absence", function()
    -- EACCES / EIO is a fact about YOUR machine, not the partner's file.
    -- Turning it into `disappeared` puts a claim about somebody else's artifact
    -- into a signed chain on the strength of a local failure.
    local a = foreign_log("s-a", 3)
    local fs = fake_fs({ [FOREIGN] = a })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w.drain()
    assert.equals(1, #events)

    for _, reason in ipairs({ "unreadable" }) do
      fs.files[FOREIGN] = { reason = reason }
      w.drain()
      assert.equals(1, #events, "a " .. reason .. " read must emit nothing")
    end

    -- ...and the file is still remembered as PRESENT, so a genuine delete
    -- afterwards still produces its one honest `disappeared`.
    fs.files[FOREIGN] = nil
    w.drain()
    assert.equals(2, #events)
    assert.equals("disappeared", events[2].data.state)
    w.dispose()
  end)

  it("CORRECTION 5: an unreadable chain is `unparseable` with all three nulls", function()
    -- "All-null or all-non-null" is true but incomplete: a port emitting `grew`
    -- with all-nulls passes the narrowing while violating the intent. EVERY
    -- unreadable chain routes here.
    local fs = fake_fs({ [FOREIGN] = "<<<<<<< HEAD\ngarbage\n" })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w.drain()

    assert.equals(1, #events)
    local d = events[1].data
    assert.equals("unparseable", d.state)
    assert.equals(core_json.NULL, d.session_id)
    assert.equals(core_json.NULL, d.seq_high)
    assert.equals(core_json.NULL, d.last_hash)
    assert.is_true(peer_observed.validate(d).ok)

    -- ...even on a SECOND observation of the same unreadable file, where
    -- `grew`/`shrank` would otherwise be reachable.
    fs.files[FOREIGN] = "<<<<<<< HEAD\ngarbage grew longer\n"
    w.drain()
    assert.equals(2, #events)
    assert.equals("unparseable", events[2].data.state)
    assert.equals(core_json.NULL, events[2].data.session_id)
    w.dispose()
  end)

  it("CORRECTION 6: there is no timer — the drain is caller-driven", function()
    -- "Or a timer, whichever is later" reads backwards: running both gives
    -- whichever is SOONER. This module owns no timer at all, so a long-idle
    -- session delays witnessing but never loses it, because stop() always
    -- drains. Asserted as the absence of any emission without a drain.
    local fs = fake_fs({ [FOREIGN] = foreign_log("s-a", 2) })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w._enqueue(FOREIGN)
    vim.wait(60, function()
      return #events > 0
    end, 10)
    assert.equals(0, #events)
    w.drain()
    assert.equals(1, #events)
    w.dispose()
  end)

  it("CORRECTION 7 is a git rule, asserted in root_commit_sha_spec", function()
    -- Placeholder-free: correction 7 (`--is-shallow-repository` needs git
    -- >= 2.15) belongs to the OTHER writer half, and is pinned by
    -- "omits when `--is-shallow-repository` is unknown (git < 2.15 exits
    -- non-zero)". Named here only so a reader of this file can account for all
    -- seven.
    assert.is_true(true)
  end)
end)

describe("peer_watcher: RULE 4 — never witness ourselves", function()
  it("this session's own .slog and .slog.meta are excluded by path", function()
    local fs = fake_fs({
      [OWN] = foreign_log("own", 3),
      [OWN .. ".meta"] = "checkpoints",
      [FOREIGN] = foreign_log("s-a", 3),
    })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w.drain()

    assert.equals(1, #events)
    assert.equals(FOREIGN, events[1].data.file)

    -- ...and the own file was never even READ. A chain cannot corroborate
    -- itself, and the reader excluding a self-witness is not a licence for the
    -- writer to produce one.
    for _, path in ipairs(fs.reads) do
      assert.is_nil(path:find(OWN, 1, true), "must not read its own file: " .. path)
    end

    -- The watcher callback drops it too, so it never even reaches the queue.
    w._enqueue(OWN)
    w.drain()
    assert.equals(1, #events)
    w.dispose()
  end)
end)

describe("peer_watcher: RULE 5 — A FOREIGN FILE IS NEVER TOUCHED", function()
  it("the module is constructed with no write-capable seam at all", function()
    -- Decision-log bug 2 was a startup recovery that QUARANTINED — renamed — a
    -- partner's log with no ownership check, which in a shared repo destroys
    -- the victim's evidence and makes git blame them for it. Watching a
    -- directory full of other students' evidence is the second place that
    -- mistake could be made.
    --
    -- Enforced structurally: the only injected capabilities are `read_file`
    -- and `list_dir`. There is no `write`, no `rename`, no `unlink` parameter,
    -- so a rename is not merely absent — it is unreachable.
    local touched = {}
    local fs = fake_fs({ [FOREIGN] = "<<<<<<< HEAD\nnot a log\n" })
    local w = peer_watcher.start({
      provenance_dir = "/tmp/ws/.provenance",
      emit = function() end,
      read_file = fs.read_file,
      list_dir = fs.list_dir,
      create_watcher = function()
        return nil
      end,
      -- Every write-shaped name a future refactor might reach for, handed in
      -- and required to stay uncalled.
      write_file = function()
        touched[#touched + 1] = "write"
      end,
      rename = function()
        touched[#touched + 1] = "rename"
      end,
      unlink = function()
        touched[#touched + 1] = "unlink"
      end,
      quarantine = function()
        touched[#touched + 1] = "quarantine"
      end,
    })

    w.drain()
    w.drain()
    assert.same({}, touched)
    -- The unreadable file is still there, byte for byte, under its own name.
    assert.equals("<<<<<<< HEAD\nnot a log\n", fs.files[FOREIGN])
    w.dispose()
  end)

  it("an unparseable foreign file is recorded and left exactly where it is", function()
    -- `state = "unparseable"` is the ENTIRE response.
    local original = "\1\2\3 binary junk \255"
    local fs = fake_fs({ [FOREIGN] = original })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w.drain()

    assert.equals(1, #events)
    assert.equals("unparseable", events[1].data.state)
    assert.equals(original, fs.files[FOREIGN])
    -- Exactly one key in the fake filesystem: nothing was renamed into a
    -- second name beside it either.
    local n = 0
    for _ in pairs(fs.files) do
      n = n + 1
    end
    assert.equals(1, n)
    w.dispose()
  end)
end)

describe("peer_watcher: RULE 2 — the callback does no I/O", function()
  it("enqueueing does not read, list, hash or emit", function()
    -- The recorder's handler budget is <1 ms p99 (PRD §4.7). Hashing a
    -- partner's multi-megabyte log on a watcher callback blows it on the one
    -- path a student notices.
    local fs = fake_fs({ [FOREIGN] = foreign_log("s-a", 3) })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })

    for _ = 1, 500 do
      w._enqueue(FOREIGN)
      w._enqueue("session-other.slog")
      w._enqueue("ignored.slog.meta")
    end

    assert.equals(0, #fs.reads)
    assert.equals(0, fs.listed)
    assert.equals(0, #events)

    -- ...and 1500 callbacks collapse to one observation per file: the SET is
    -- the rate limit, structurally rather than by timer.
    w.drain()
    assert.equals(1, #events) -- session-other.slog is not on the fake disk
    w.dispose()
  end)
end)

describe("peer_watcher: THE CHAIN-ADVANCE SEAM IS ATOMIC", function()
  --- Build a real session host and a watcher whose reads emit a competing
  --- event, so a drain that interleaved I/O with emission would be visible as
  --- an out-of-order chain.
  local function host_with_interleaving_reads(files, emit_during_read)
    local entries = {}
    local host = session_host.new({
      session_id = "own-session",
      clock = {
        now = function()
          return 0
        end,
        wall = function()
          return "2026-01-01T00:00:00.000Z"
        end,
      },
      on_entry = function(entry)
        entries[#entries + 1] = entry
      end,
    })

    local fs = fake_fs(files)
    local base_read = fs.read_file
    fs.read_file = function(abs)
      -- A CONCURRENT EMITTER, firing in the middle of the drain's I/O phase.
      -- This is the heartbeat, or doc.change, or git wiring landing while a
      -- partner's log is being hashed.
      if emit_during_read then
        host.emit("session.heartbeat", { focused = true })
      end
      return base_read(abs)
    end

    local w = start(fs, { emit = host.emit })
    return host, w, entries, fs
  end

  it("no other emitter can land BETWEEN two peer.observed entries", function()
    -- If the reads and the emits were interleaved — one read, one emit, one
    -- read, one emit — the heartbeats fired during each read would appear
    -- between the peer.observed entries. Because phase 1 does every read and
    -- phase 2 does every emit, the peer.observed entries are CONTIGUOUS.
    --
    -- This is the mutation that matters most: an `await`-shaped step in the
    -- drain reintroduces the interleaving that manufactures `chain_integrity`
    -- and `seq_gaps` findings against innocent students.
    local host, w, entries = host_with_interleaving_reads({
      ["session-aaa.slog"] = foreign_log("s-a", 2),
      ["session-bbb.slog"] = foreign_log("s-b", 3),
      ["session-ccc.slog"] = foreign_log("s-c", 4),
    }, true)

    w.drain()

    local kinds = {}
    for _, e in ipairs(entries) do
      kinds[#kinds + 1] = e.kind
    end

    -- Three heartbeats (one per read) then three witnesses, in that order.
    assert.same({
      "session.heartbeat",
      "session.heartbeat",
      "session.heartbeat",
      "peer.observed",
      "peer.observed",
      "peer.observed",
    }, kinds)

    -- Stated as the invariant rather than as a literal, so a fourth partner
    -- log does not need this list rewritten: the peer.observed run is
    -- contiguous.
    local first, last
    for i, kind in ipairs(kinds) do
      if kind == "peer.observed" then
        first = first or i
        last = i
      end
    end
    assert.equals(3, last - first + 1)

    -- ...and the chain itself is contiguous and valid end to end.
    local prev = hash_chain.GENESIS_PREV_HASH
    for i, entry in ipairs(entries) do
      assert.equals(i - 1, entry.seq)
      assert.equals(prev, entry.prev_hash)
      prev = entry.hash
    end
    host.emit("session.end", { reason = "test" })
    w.dispose()
  end)

  it("drain() is synchronous: every entry is chained before it returns", function()
    -- No `vim.schedule`, no `vim.wait`, no uv async callback. The proof is that
    -- the entries exist the instant drain() returns, with no loop pumping.
    local host, w, entries = host_with_interleaving_reads({
      ["session-aaa.slog"] = foreign_log("s-a", 2),
      ["session-bbb.slog"] = foreign_log("s-b", 2),
    }, false)

    w.drain()
    assert.equals(2, #entries)
    assert.equals("peer.observed", entries[1].kind)
    assert.equals("peer.observed", entries[2].kind)

    -- Pumping the event loop afterwards must produce nothing more — a deferred
    -- emit would show up here.
    vim.wait(50, function()
      return #entries > 2
    end, 10)
    assert.equals(2, #entries)
    host.emit("session.end", { reason = "test" })
    w.dispose()
  end)

  it("emissions are deterministically ORDERED, so two runs chain identically", function()
    -- A drain over several files must emit in one fixed order or the same
    -- session over the same directory produces two different chains.
    local files = {
      ["session-ccc.slog"] = foreign_log("s-c", 2),
      ["session-aaa.slog"] = foreign_log("s-a", 2),
      ["session-bbb.slog"] = foreign_log("s-b", 2),
    }
    local seen = {}
    for run = 1, 3 do
      local events, emit = recorder()
      local fs = fake_fs(vim.deepcopy(files))
      local w = start(fs, { emit = emit })
      w.drain()
      local order = {}
      for _, e in ipairs(events) do
        order[#order + 1] = e.data.file
      end
      seen[run] = order
      w.dispose()
    end
    assert.same({ "session-aaa.slog", "session-bbb.slog", "session-ccc.slog" }, seen[1])
    assert.same(seen[1], seen[2])
    assert.same(seen[1], seen[3])
  end)

  it("a SUPPRESSED observation consumes no seq — the chain stays contiguous", function()
    -- Everything this module declines to emit (an unchanged file, a local read
    -- error, a delete for a never-seen file) must leave NO hole. A hole in the
    -- seq run reads to validation check 4 (seq_gaps) as a DELETED ENTRY.
    local host, w, entries = host_with_interleaving_reads({
      [FOREIGN] = foreign_log("s-a", 3),
    }, false)

    w.drain() -- one observation
    for _ = 1, 10 do
      w.drain() -- unchanged: nothing
    end
    host.emit("session.heartbeat", { focused = true })

    assert.equals(2, #entries)
    local prev = hash_chain.GENESIS_PREV_HASH
    for i, entry in ipairs(entries) do
      assert.equals(i - 1, entry.seq)
      assert.equals(prev, entry.prev_hash)
      prev = entry.hash
    end
    w.dispose()
  end)
end)

describe("peer_watcher: degradation and teardown", function()
  it("a throwing read_file costs that file only, not the others or the session", function()
    local fs = fake_fs({
      ["session-aaa.slog"] = foreign_log("s-a", 2),
      ["session-bbb.slog"] = foreign_log("s-b", 2),
    })
    local base = fs.read_file
    fs.read_file = function(abs)
      if abs:find("aaa", 1, true) then
        error("boom")
      end
      return base(abs)
    end
    local events, emit = recorder()
    local w = start(fs, { emit = emit, on_debug = function() end })

    assert.has_no.errors(function()
      w.drain()
    end)
    assert.equals(1, #events)
    assert.equals("session-bbb.slog", events[1].data.file)
    w.dispose()
  end)

  it("a throwing list_dir and a failing watcher both degrade, never raise", function()
    local fs = fake_fs({ [FOREIGN] = foreign_log("s-a", 2) })
    local w = peer_watcher.start({
      provenance_dir = "/tmp/ws/.provenance",
      emit = function() end,
      read_file = fs.read_file,
      list_dir = function()
        error("scandir failed")
      end,
      create_watcher = function()
        error("no fs_event available")
      end,
      on_debug = function() end,
    })
    assert.has_no.errors(function()
      w.drain()
    end)
    -- A watcher that could not be created costs promptness, never recording.
    assert.is_false(w._watching)
    assert.has_no.errors(function()
      w.dispose()
    end)
  end)

  it("dispose() is idempotent and makes drain() inert", function()
    local fs = fake_fs({ [FOREIGN] = foreign_log("s-a", 2) })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w.dispose()
    w.dispose()
    w.drain()
    assert.equals(0, #events)
    assert.equals(0, #fs.reads)
  end)

  it("a re-entrant drain is refused rather than interleaved", function()
    -- A drain that emitted enough entries to trip the checkpoint cadence must
    -- not recurse into itself mid-batch: the second pass would see a
    -- half-updated `last_seen` and could double-witness.
    local fs = fake_fs({ [FOREIGN] = foreign_log("s-a", 2) })
    local events = {}
    local w
    w = start(fs, {
      emit = function(kind, data)
        events[#events + 1] = { kind = kind, data = data }
        w.drain() -- the checkpoint cadence firing from inside an emit
      end,
    })
    w.drain()
    assert.equals(1, #events)
    w.dispose()
  end)

  it("a real uv fs_event on a real directory is created and torn down cleanly", function()
    -- The default seam, exercised once against the real thing: a leaked libuv
    -- handle keeps headless Neovim from exiting, which is why every watcher in
    -- this plugin has an explicit dispose().
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    local w = peer_watcher.start({
      provenance_dir = dir,
      emit = function() end,
    })
    assert.is_true(w._watching)
    assert.has_no.errors(function()
      w.drain()
    end)
    assert.has_no.errors(function()
      w.dispose()
    end)
    assert.has_no.errors(function()
      w.dispose()
    end)
    pcall(vim.fn.delete, dir, "rf")
  end)
end)

describe("peer_watcher: the payload names a FILE and a CHAIN POSITION, nothing else", function()
  it("no identity, no absolute path, no key, no author", function()
    local fs = fake_fs({ [FOREIGN] = foreign_log("s-a", 3) })
    local events, emit = recorder()
    local w = start(fs, { emit = emit })
    w.drain()

    local keys = {}
    for k in pairs(events[1].data) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    assert.same(peer_observed.PAYLOAD_KEYS, keys)

    local serialized = core_json.canonicalize(events[1].data)
    -- `file` is a BASENAME: no path outside `.provenance/`, and in particular
    -- not the absolute path the recorder actually read.
    assert.equals(FOREIGN, events[1].data.file)
    assert.is_nil(serialized:find("/tmp/ws", 1, true))
    assert.is_nil(serialized:find("student_ref", 1, true))
    assert.is_nil(serialized:find("@", 1, true))
    assert.is_nil(serialized:find("author", 1, true))
    w.dispose()
  end)
end)
