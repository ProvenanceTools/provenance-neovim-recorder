--- slog_ownership.lua — WHOSE `.slog` IS THIS?
---
--- `.provenance/` is committed, so in a shared repo (two partners, one git
--- repo — the standard CS 61B/61C layout) a `git pull` drops the PARTNER'S
--- `.slog` into the same directory this recorder writes into. Every module
--- that walks that directory has to answer one question first: is this file
--- mine? This module is the only place that question is answered, and it is
--- deliberately incapable of doing anything about the answer.
---
--- ===========================================================================
--- WHY THIS MODULE EXISTS — decision-log bug 2, live in this port
--- ===========================================================================
---
--- `startup/chain_recovery.lua` listed every `*.slog`, took the
--- alphabetically last one as "the previous session", and RENAMED it to
--- `<slog>.corrupt-<ts>` whenever it could not read, parse or chain-validate
--- it. With no ownership check, in a shared repo that is:
---
---   1. **Destruction of a partner's evidence.** A partner whose editor is
---      open right now has no `session.end`; a log mid-`git checkout` is
---      truncated; a badly-merged one carries conflict markers. Any of those
---      fails to validate. `commands/seal.lua` skips `.corrupt-` files, so
---      the rename removes the partner's log from the submission entirely —
---      and because `.provenance/` is committed, git history shows the
---      INNOCENT student doing it.
---   2. **A free attack.** Flip one byte of your partner's log and their own
---      partner's tooling deletes it for you.
---   3. **A false relationship.** `prev_session_id` read off whichever log
---      sorted last could name a session belonging to a DIFFERENT student,
---      asserting a contributor chain the evidence does not support.
---
--- `watch/peer_watcher.lua` rule 5 already fixed the writer side of this
--- ("a foreign file is never touched", enforced by holding no write-capable
--- handle at all). This module is the same rule for the reader side.
---
--- ===========================================================================
--- THE SIGNAL: `session.start.identity.enrollment.student_ref`, AND ONLY IT
--- ===========================================================================
---
--- Recovery runs BEFORE this session has minted its own `session_id`, so
--- "is this mine?" cannot be answered by comparing session ids — there is
--- nothing yet to compare. The only identity that survives across sessions is
--- `student_ref` (program spec §5a), which this port already writes into
--- `session.start.identity.enrollment` via `identity/session_identity.lua`.
---
--- It is emphatically NOT:
---
---   - `machine_id` — salted with the session id in `session/recorder_context.lua`,
---     so it can never match across two sessions, not even the same student's.
---   - `session_pubkey` — a fresh ephemeral keypair per session, by design.
---   - the `.slog` FILENAME uuid — minted per file and unrelated to any
---     identity (the two-uuid rule).
---
--- Only the FIRST LINE of a candidate is parsed. `session.start` is always
--- seq 0, so one line is enough, and startup cost must not scale with the
--- size of a partner's log.
---
--- ===========================================================================
--- THE THREE CLASSES
--- ===========================================================================
---
---   own           both refs present and equal        eligible: may be selected,
---                                                    linked, and quarantined
---   foreign       both present and different, OR     NEVER touched. Not selected,
---                 we have none and it has one        not linked, not renamed
---   unattributed  the candidate names nobody         eligible ONLY when this
---                                                    recorder is itself unattributed
---
--- The asymmetric `foreign` case — we have NO ref, the candidate HAS one — is
--- deliberate. We cannot claim to be a contributor we cannot name, and the
--- costs are asymmetric: misfiling our own pre-enrollment log as foreign loses
--- a back-pointer, while misfiling a partner's log as ours destroys it.
---
--- Why `unattributed` stays eligible for an unattributed recorder: when
--- nothing in the directory carries an identity, the directory is
--- indistinguishable from a solo one. Refusing to act there would silently
--- switch off crash recovery for every student who has not enrolled, which is
--- a behaviour change well beyond fixing a bug. When THIS recorder DOES hold
--- an identity, an unattributed file is a file we cannot prove is ours, so we
--- leave it alone.
---
--- ===========================================================================
--- RESIDUAL GAP — stated, not papered over
--- ===========================================================================
---
--- **When NEITHER partner has enrolled, every file in the directory is
--- `unattributed` and no signal exists that could separate them.** Both
--- defects above remain reachable in exactly that configuration. This module
--- does not fix it and cannot: closing it needs enrollment (program spec §5a)
--- or peer witnessing (`watch/peer_watcher.lua`, which testifies that a log
--- existed even after someone removes it). What this module does guarantee is
--- that the moment EITHER side is enrolled, the enrolled recorder stops being
--- able to touch anything it cannot prove is its own.
---
--- ===========================================================================
--- NO WRITE-CAPABLE SEAM
--- ===========================================================================
---
--- `select_eligible` is handed a READ function and nothing else — the same
--- structural rule `watch/peer_watcher.lua` follows. There is no rename, no
--- delete and no write reachable from this module even by mistake, so the
--- scan that decides ownership physically cannot act on a file it is in the
--- middle of classifying.
local M = {}

--- Table-typed field access that treats `vim.NIL`, scalars and absent keys
--- alike as "not there". Narrowed by hand rather than by a schema: 1.x logs
--- have no `identity` block at all, and this runs over a file written by a
--- possibly-different recorder version, possibly a different EDITOR's
--- recorder. "Absent" must never become "throws".
local function child_table(tbl, key)
  if type(tbl) ~= "table" then
    return nil
  end
  local value = tbl[key]
  if type(value) ~= "table" then
    return nil
  end
  return value
end

--- `data.identity.enrollment.student_ref` off a decoded `session.start`
--- payload, or nil when any hop is missing or the wrong shape.
--- @param data any
--- @return string|nil
local function student_ref_of_payload(data)
  local enrollment = child_table(child_table(data, "identity"), "enrollment")
  if enrollment == nil then
    return nil
  end
  local ref = enrollment.student_ref
  if type(ref) == "string" and #ref > 0 then
    return ref
  end
  return nil
end

--- The `student_ref` a `.slog` claims, read from its FIRST LINE only.
---
--- Returns nil for anything that is not a parseable `session.start` carrying a
--- non-empty `student_ref` — including a nil `text`, i.e. a file that could
--- not be read at all. A file we cannot read cannot tell us whose it is, so it
--- is `unattributed`, never `own`.
--- @param text string|nil  raw `.slog` bytes
--- @return string|nil
function M.student_ref_of_slog_text(text)
  if type(text) ~= "string" then
    return nil
  end
  local first_line = text:match("^([^\n]*)")
  if first_line == nil or first_line:match("^%s*$") ~= nil then
    return nil
  end
  local ok, decoded = pcall(vim.json.decode, first_line)
  if not ok or type(decoded) ~= "table" then
    return nil
  end
  if decoded.kind ~= "session.start" then
    return nil
  end
  return student_ref_of_payload(decoded.data)
end

--- @param own_student_ref string|nil        this session's ref, nil = unenrolled
--- @param candidate_student_ref string|nil  the candidate's ref, nil = unattributed
--- @return string  "own" | "foreign" | "unattributed"
function M.classify(own_student_ref, candidate_student_ref)
  -- A candidate that names nobody can never be PROVEN ours, whoever we are.
  if candidate_student_ref == nil then
    return "unattributed"
  end
  if own_student_ref == nil then
    return "foreign"
  end
  if candidate_student_ref == own_student_ref then
    return "own"
  end
  return "foreign"
end

--- May this recorder select, link to, and (if corrupt) quarantine a candidate
--- of the given class? See the class table in the module docstring.
--- @param ownership string
--- @param own_student_ref string|nil
--- @return boolean
function M.is_eligible(ownership, own_student_ref)
  if ownership == "own" then
    return true
  end
  if ownership == "foreign" then
    return false
  end
  return own_student_ref == nil
end

--- Walk an ALREADY-SORTED list of `.slog` paths from the end and return the
--- first ELIGIBLE one, with the text already read so the caller need not
--- re-read it.
---
--- Walking from the end preserves this port's documented "alphabetically last
--- wins" tie-break (see `chain_recovery.lua`) restricted to eligible files,
--- and it means the solo case still reads exactly ONE file — the ownership
--- gate costs a solo student nothing. In a shared repo we read backwards past
--- the partner's logs until we reach one of our own; each such read is one
--- file, first line parsed, text discarded.
---
--- @param read_slog function  (path) -> string|nil. READ ONLY: this is the
---   entire capability this scan is given, so a foreign file cannot be renamed,
---   truncated or deleted from here even by mistake.
--- @param sorted_paths table  list of `.slog` paths, ascending
--- @param own_student_ref string|nil
--- @return table|nil  { path = string, text = string|nil }, or nil when no
---   candidate is eligible (every file in the directory is someone else's)
function M.select_eligible(read_slog, sorted_paths, own_student_ref)
  for i = #sorted_paths, 1, -1 do
    local path = sorted_paths[i]
    -- A read failure is not an error here: it yields a nil text, which reads
    -- as `unattributed`, which an enrolled recorder is not allowed to touch.
    local read_ok, text = pcall(read_slog, path)
    if not read_ok then
      text = nil
    end
    local ownership = M.classify(own_student_ref, M.student_ref_of_slog_text(text))
    if M.is_eligible(ownership, own_student_ref) then
      return { path = path, text = text }
    end
  end
  return nil
end

return M
