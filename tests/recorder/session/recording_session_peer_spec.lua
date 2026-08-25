--- recording_session peer-witnessing wiring (program spec §7 mechanism 2,
--- collaboration spec §5.5, Tier 4.1).
---
--- `peer_watcher_spec.lua` covers the watcher's own rules against a fake
--- filesystem. THIS file covers the three things only the live session can get
--- wrong, all against real `vim.uv` I/O and a real hash chain:
---
---   1. The drain runs where the contract says — on the checkpoint cadence and
---      once at stop() — so a partner's log is witnessed at all.
---   2. The observation lands in the real `.slog`, chained, and the chain is
---      still contiguous and valid afterwards.
---   3. THE CHAIN ADVANCE IS ATOMIC IN THE SESSION HOST ITSELF. A watcher adds
---      an emitter; this port is race-free only because nothing yields between
---      the host reading `prev_hash` and advancing `seq`. The provcode port's
---      equivalent test caught a mutation in the session host, not in the
---      watcher — so it is driven here, through the real host, not against a
---      stub.
local recording_session = require("provenance.recorder.session.recording_session")
local core_clock = require("provenance.core.clock")
local hash_chain = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local ndjson = require("provenance.core.ndjson")
local peer_observed = require("provenance.core.peer_observed")
local sha256 = require("provenance.core.sha256")

local function new_scratch()
  local scratch = { bufs = {}, dirs = {}, session = nil }

  function scratch.workspace()
    local dir = vim.fs.normalize(vim.fn.tempname())
    vim.fn.mkdir(dir, "p")
    table.insert(scratch.dirs, dir)
    return dir
  end

  function scratch.write_file(path, content)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    local f = assert(io.open(path, "w"))
    f:write(content)
    f:close()
  end

  function scratch.edit(path)
    vim.cmd("edit " .. vim.fn.fnameescape(path))
    local buf = vim.api.nvim_get_current_buf()
    table.insert(scratch.bufs, buf)
    return buf
  end

  local next_line = 0
  function scratch.make_entry(buf)
    next_line = next_line + 1
    local n = vim.api.nvim_buf_line_count(buf)
    vim.api.nvim_buf_set_lines(buf, n, n, false, { "line-" .. tostring(next_line) })
  end

  function scratch.teardown()
    if scratch.session then
      pcall(scratch.session.stop)
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
    for _, dir in ipairs(scratch.dirs) do
      pcall(vim.fn.delete, dir, "rf")
    end
  end

  return scratch
end

local function dev_manifest()
  return {
    assignment_id = "hw3",
    semester = "fa25",
    sig = ("ab"):rep(64),
    files_under_review = { "foo.txt" },
  }
end

local function read_all(path)
  return table.concat(vim.fn.readfile(path, "b"), "\n")
end

--- A REAL foreign log, chained through this port's own primitives, so what the
--- watcher reads out of it is read out of the same bytes a partner's recorder
--- would have written.
local function write_foreign_log(dir, uuid, session_id, n_entries)
  local prev = hash_chain.GENESIS_PREV_HASH
  local lines = {}
  local last
  for seq = 0, n_entries - 1 do
    local kind = seq == 0 and "session.start" or "session.heartbeat"
    local data = seq == 0 and { session_id = session_id } or { focused = true }
    local env =
      envelope.new(seq, seq * 10, "2026-01-01T00:00:0" .. (seq % 10) .. ".000Z", kind, data)
    local entry = hash_chain.chain_entry(prev, env)
    prev = entry.hash
    last = entry
    lines[#lines + 1] = ndjson.serialize_entry(entry)
  end
  local text = table.concat(lines)
  local path = dir .. "/session-" .. uuid .. ".slog"
  local f = assert(io.open(path, "w"))
  f:write(text)
  f:close()
  return path, text, last
end

--- Every entry in the session's own `.slog`, parsed.
local function slog_entries(session)
  local parsed = ndjson.parse_entries(read_all(session.slog_path))
  assert.is_true(parsed.ok, "the session's own .slog must parse")
  return parsed.value
end

local function of_kind(entries, kind)
  local out = {}
  for _, e in ipairs(entries) do
    if e.kind == kind then
      out[#out + 1] = e
    end
  end
  return out
end

--- The chain is contiguous (no seq hole) and every prev_hash links.
--- A hole reads to validation check 4 (seq_gaps) as a DELETED ENTRY, which is
--- the exact false accusation every rule in this area exists to prevent.
local function assert_chain_intact(entries)
  local prev = hash_chain.GENESIS_PREV_HASH
  for i, entry in ipairs(entries) do
    assert.equals(i - 1, entry.seq, "seq hole at index " .. i)
    assert.equals(prev, entry.prev_hash, "broken link at seq " .. entry.seq)
    prev = entry.hash
  end
end

describe("recording_session: peer witnessing", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  local function start_session(extra_opts)
    local workspace = scratch.workspace()
    local provenance_dir = workspace .. "/.provenance"
    vim.fn.mkdir(provenance_dir, "p")
    local path = workspace .. "/foo.txt"
    scratch.write_file(path, "line0\n")

    scratch.session = recording_session.start(vim.tbl_extend("force", {
      workspace = workspace,
      provenance_dir = provenance_dir,
      manifest = dev_manifest(),
      clock = core_clock.fixed(0, 0),
    }, extra_opts or {}))

    return scratch.edit(path), provenance_dir
  end

  it("witnesses a partner's .slog at stop(), into this session's own chain", function()
    local _, provenance_dir = start_session()
    local _, text, last = write_foreign_log(
      provenance_dir,
      "7f3a1c22-9b0e-4d51-8a77-2c6e5d0b41af",
      "4e2d9c10-55af-4b3e-9d21-8f0c7a6b3e55",
      6
    )

    scratch.session.stop()

    local entries = slog_entries(scratch.session)
    local witnesses = of_kind(entries, "peer.observed")
    assert.equals(1, #witnesses)

    local d = witnesses[1].data
    assert.equals("session-7f3a1c22-9b0e-4d51-8a77-2c6e5d0b41af.slog", d.file)
    assert.equals(sha256.hex(text), d.sha256)
    assert.equals(#text, d.bytes)
    assert.equals("4e2d9c10-55af-4b3e-9d21-8f0c7a6b3e55", d.session_id)
    assert.equals(5, d.seq_high)
    assert.equals(last.hash, d.last_hash)
    assert.equals("appeared", d.state)
    assert.is_true(peer_observed.validate(d).ok)

    -- It landed BEFORE session.end, so it is inside the session it belongs to.
    assert.equals("session.end", entries[#entries].kind)
    assert.is_true(witnesses[1].seq < entries[#entries].seq)

    assert_chain_intact(entries)
  end)

  it("witnesses on the CHECKPOINT CADENCE, not only at stop()", function()
    -- Writer contract rule 3: the same cadence, and the same serialized chain,
    -- as the rolling seal. A session that runs for hours must not hold every
    -- observation until shutdown, because a session that never reaches stop()
    -- would then testify to nothing.
    local buf, provenance_dir = start_session({ checkpoint_interval = 3 })
    write_foreign_log(provenance_dir, "aaaa1111-0000-0000-0000-000000000000", "partner-a", 4)

    -- session.start is seq 0; two edits trip the interval-3 cadence.
    scratch.make_entry(buf)
    scratch.make_entry(buf)
    -- The checkpoint scheduler defers via vim.schedule, and the drain runs
    -- inside its persist step.
    vim.wait(2000, function()
      return #of_kind(slog_entries(scratch.session), "peer.observed") > 0
    end, 20)

    local witnesses = of_kind(slog_entries(scratch.session), "peer.observed")
    assert.equals(1, #witnesses)
    assert.equals("partner-a", witnesses[1].data.session_id)

    -- ...and the session had not stopped when it happened.
    scratch.session.stop()
    assert_chain_intact(slog_entries(scratch.session))
  end)

  it("never witnesses its OWN .slog or .slog.meta", function()
    -- A chain cannot corroborate itself. The session's own files are the only
    -- things in `.provenance/` here, so a self-witnessing port would emit two
    -- observations and this asserts zero.
    local _, provenance_dir = start_session()
    assert.is_true(vim.fn.filereadable(scratch.session.slog_path) == 1)

    scratch.session.stop()

    local entries = slog_entries(scratch.session)
    assert.equals(0, #of_kind(entries, "peer.observed"))
    assert_chain_intact(entries)

    -- Nothing else appeared in `.provenance/` either: witnessing never writes.
    local names = vim.fn.readdir(provenance_dir)
    for _, name in ipairs(names) do
      assert.is_true(
        name:sub(-5) == ".slog" or name:sub(-10) == ".slog.meta" or name:match("^manifest%-") ~= nil,
        "unexpected file in .provenance/: " .. name
      )
    end
  end)

  it("A FOREIGN FILE IS NEVER TOUCHED — bytes, name and count all unchanged", function()
    -- Decision-log bug 2: a recorder that quarantined (renamed) its partner's
    -- log destroys the victim's evidence and makes git blame them for it.
    -- Driven with a file that CANNOT be parsed, which is the case that tempts a
    -- port into "cleaning it up".
    local _, provenance_dir = start_session()
    local hostile = provenance_dir .. "/session-bbbb2222-0000-0000-0000-000000000000.slog"
    local original = "<<<<<<< HEAD\n{not json}\n=======\n{also not}\n>>>>>>> theirs\n"
    scratch.write_file(hostile, original)

    local before = vim.fn.readdir(provenance_dir)
    table.sort(before)

    scratch.session.stop()

    -- Same bytes.
    assert.equals(original, read_all(hostile))
    -- Same name, and no new name beside it (no `.quarantine`, no `.bak`, no
    -- `.corrupt`).
    local after = vim.fn.readdir(provenance_dir)
    table.sort(after)
    for _, name in ipairs(before) do
      local still_there = false
      for _, n in ipairs(after) do
        if n == name then
          still_there = true
        end
      end
      assert.is_true(still_there, "a file disappeared from .provenance/: " .. name)
    end
    for _, name in ipairs(after) do
      assert.is_nil(name:find("quarantine", 1, true), "quarantined a foreign file: " .. name)
      assert.is_nil(name:find(".bak", 1, true))
      assert.is_nil(name:find("corrupt", 1, true))
    end

    -- ...and recording the state is the ENTIRE response.
    local witnesses = of_kind(slog_entries(scratch.session), "peer.observed")
    assert.equals(1, #witnesses)
    assert.equals("unparseable", witnesses[1].data.state)
  end)

  it("THE CHAIN ADVANCE IS ATOMIC: a concurrent emitter cannot split the drain", function()
    -- The mutation this exists to catch is a DEFERRED emit in the drain — a
    -- `vim.schedule`, a `vim.wait`, a uv async callback — between reading a
    -- partner's log and chaining the observation. With one, the entries land
    -- after stop() has flushed and closed the writer, or land out of order
    -- relative to the editor's own emitter, and the chain the analyzer reads is
    -- broken. provcode's equivalent test caught a mutation in the SESSION HOST
    -- rather than in the watcher, which is why this drives the real host, the
    -- real doc-wiring emitter and the real `.slog` rather than a stub.
    --
    -- Scope note, so this is not read as proving more than it does: the FINER
    -- mutation — emitting inside the read loop, still synchronously, so the
    -- observations interleave with a competing emitter — is caught by
    -- peer_watcher_spec's "no other emitter can land BETWEEN two peer.observed
    -- entries", which fires its competing emitter from inside each read. That
    -- test also uses a real `session_host`. This one covers the coarse case and
    -- the end-to-end chain.
    local buf, provenance_dir = start_session()
    for i = 1, 4 do
      write_foreign_log(
        provenance_dir,
        string.format("cccc%04d-0000-0000-0000-000000000000", i),
        "partner-" .. i,
        i + 1
      )
    end

    -- A competing emitter, firing continuously while the drain runs. Real
    -- buffer edits go through doc_wiring -> host.emit, the same chokepoint the
    -- watcher uses.
    local ticking = true
    local timer = (vim.uv or vim.loop).new_timer()
    timer:start(0, 1, function()
      if not ticking then
        return
      end
      vim.schedule(function()
        if ticking then
          pcall(scratch.make_entry, buf)
        end
      end)
    end)

    vim.wait(30, function()
      return false
    end, 5)
    scratch.session.stop()
    ticking = false
    pcall(function()
      timer:stop()
      timer:close()
    end)

    local entries = slog_entries(scratch.session)
    local witnesses = of_kind(entries, "peer.observed")
    assert.equals(4, #witnesses)

    -- The four observations are CONTIGUOUS in seq: nothing landed between them.
    -- An interleaved drain would show doc.change entries in the gaps.
    local first = witnesses[1].seq
    for i, w in ipairs(witnesses) do
      assert.equals(first + i - 1, w.seq, "a foreign emitter split the drain")
    end

    -- ...and the chain the whole session wrote is intact end to end. This is
    -- the property a race destroys: a duplicated or skipped seq, or a
    -- prev_hash that does not link, reads as tampering.
    assert_chain_intact(entries)
  end)

  it("a suppressed observation burns NO seq across many drains", function()
    -- Everything the watcher declines to emit — an unchanged file at every
    -- subsequent checkpoint — must leave the chain contiguous. A hole reads to
    -- validation check 4 (seq_gaps) as a deleted entry.
    local buf, provenance_dir = start_session({ checkpoint_interval = 2 })
    write_foreign_log(provenance_dir, "dddd3333-0000-0000-0000-000000000000", "partner-d", 3)

    for _ = 1, 12 do
      scratch.make_entry(buf)
      vim.wait(20, function()
        return false
      end, 5)
    end
    scratch.session.stop()

    local entries = slog_entries(scratch.session)
    -- Many checkpoints, ONE witness: the file never changed after the first
    -- observation.
    assert.equals(1, #of_kind(entries, "peer.observed"))
    assert_chain_intact(entries)
  end)

  it("witnessing failures never stop recording", function()
    -- Recording matters more than witnessing. A `.provenance/` that cannot be
    -- listed, or a log that cannot be read, must cost the observation and
    -- nothing else.
    local buf, provenance_dir = start_session()
    local unreadable = provenance_dir .. "/session-eeee4444-0000-0000-0000-000000000000.slog"
    scratch.write_file(unreadable, "whatever")
    -- 0o000: EACCES on read. Skipped when running as root, where chmod does
    -- not deny the owner.
    vim.fn.setfperm(unreadable, "---------")
    local denied = vim.fn.filereadable(unreadable) == 0

    scratch.make_entry(buf)
    assert.has_no.errors(function()
      scratch.session.stop()
    end)

    local entries = slog_entries(scratch.session)
    assert_chain_intact(entries)
    assert.is_true(#of_kind(entries, "doc.change") >= 1)
    if denied then
      -- CORRECTION 4: a local read failure is a fact about THIS machine, not
      -- about the partner's file, so it produces no observation at all.
      assert.equals(0, #of_kind(entries, "peer.observed"))
    end
    vim.fn.setfperm(unreadable, "rw-------")
  end)
end)
