--- The three `session.start` CAPABILITY REPORTS — collaboration spec §5.6.
--- Lua port of log-core's `session-capabilities.ts`. Read that file for the
--- full rationale; this module keeps the cross-language contract a writer and
--- a reader both need: the two closed enums, the `file_scope` shape/path
--- validator, and a narrow reader for each field.
---
--- ## Why a WRITER needs the READER
---
--- Same reason as `git_event.lua` and `peer_observed.lua`: the narrowing is a
--- CROSS-LANGUAGE CONTRACT with four consumers (this monorepo's analyzer and
--- server through `analysis-core`, plus the two sibling recorder repos), not a
--- private detail of one reader. The write side
--- (`recorder/session/recorder_context.lua`'s `build_file_scope` call) routes
--- through `M.build_file_scope` — this module's own path validator — rather
--- than a private regex, exactly as `git_payloads.lua` routes
--- `root_commit_sha` through `git_event.is_usable_discriminator`. A writer
--- that shape-checks with its own copy of the rule can emit a value its own
--- reader rejects; a writer that runs the reader cannot.
---
--- ## What a capability report is, and what it is emphatically not
---
--- A capability report says "I could not". A capture-policy knob (see
--- `core/capture_policy.lua`) says "I was told not to". Those are different
--- facts with different owners: a knob is a course-signed manifest field a
--- professor controls, a capability report is the recorder describing the
--- machine it ran on. Nothing here is policy-gated, and nothing here is ever
--- a Flag, a validation finding, a severity or a score. Facts only.
---
--- ## Absent is the ordinary case, permanently
---
--- Every bundle recorded before §5.6 landed carries none of these fields, and
--- every field is optional permanently (1.x support is permanent). `absent`
--- MUST be read as "this recorder does not report the capability" — never as
--- "unavailable". Collapsing the two would make every legacy bundle claim its
--- own capture was broken.
---
--- ## Writers OMIT, never `null`
---
--- Omission and `null` canonicalize differently and therefore chain to
--- different hashes, exactly as `parents: []` and an absent `parents` do (see
--- `events/git_payloads.lua`). `M.build_file_scope` returns `nil` for the
--- caller to leave the key OUT of the payload table entirely — assigning a
--- Lua `nil` to a table key already omits it, so the caller must never assign
--- `core_json.NULL` here instead. Readers accept `null` as absence so a
--- nonconforming log still parses; a writer that emits it is nonconforming.
---
--- ## `not_owned` is unreachable from THIS recorder's own writer
---
--- `git_capture` is a three-value enum in the cross-language contract because
--- VS Code's `vscode.git` extension can see repositories across an entire
--- multi-root workspace and route by ownership, and because provjet's IDE
--- performs a single PROJECT-WIDE VCS-root discovery (every nested `.git` the
--- IDE has indexed) and then routes each observed repo to a session by a
--- path-prefix predicate (`RecorderSessionManager.sessionOwning`) — so a repo
--- the discovery step finds that matches no session's root is exactly
--- `not_owned`. That requires a SHARED discovery/routing layer sitting between
--- "git observation" and "which session gets this event", one that can find a
--- repo and then fail to route it.
---
--- provnvim structurally has no such layer, and this was re-checked against
--- the concurrent-session case specifically (program spec S0: `registry.lua`
--- keeps a root -> session map so more than one assignment root CAN record at
--- once — the premise that broke the equivalent claim for provjet). Even so:
--- `recording_session.lua` calls `git_wiring.start({ workspace = <that
--- session's own root>, ... })` once per session (see
--- `recorder/session/recording_session.lua`'s step 1e), and `git_wiring.lua`'s
--- repo discovery for that call is entirely LOCAL to `workspace` — `git -C
--- <workspace> rev-parse --git-dir` (which is git's own upward directory
--- search, not a repo enumeration) and an `fs_stat` of `<workspace>/.git`.
--- There is no step, anywhere, that lists "every repo this Neovim instance can
--- see" and then matches roots against it. A second, concurrently-recording
--- session's repository is not merely unmatched by this session's routing —
--- it is never looked at, because the seam is scoped by construction to one
--- session's own `workspace` and cannot observe another session's `-C`
--- argument. So there is no "git worked, and pointed at a repo that belongs to
--- someone else" state to land in: whatever `git -C workspace ...` finds (if
--- anything) is, by construction, this session's own answer.
---
--- This also covers the classic "shared class repo, assignment is a
--- subdirectory" layout (the repo root sits ABOVE the assignment root) without
--- extra code: `git -C <workspace> rev-parse --git-dir` walks upward exactly
--- like any other git command, so it finds and returns the ancestor `.git`
--- (verified empirically: `git -C <subdir> rev-parse --git-dir` from inside a
--- parent repo prints the parent's `.git`, absolute-or-relative-and-resolved
--- by `resolve_git_dir`). provjet's `sessionOwning` predicate, by contrast, is
--- `normalized.startsWith(root)` — it requires the DISCOVERED repo path to be
--- at-or-below the session's root, so a repo root ABOVE the assignment root
--- fails that prefix test and the event is dropped (the unfixed defect shape
--- provjet's agent flagged as "bug 3", left alone as out of scope there).
--- provnvim never asks that question at all: there is no discovered-repo-path
--- to compare against a root, only "did `git -C workspace` find something",
--- so the above/below distinction that trips `sessionOwning` does not arise
--- here.
---
--- (One thing this does NOT claim: if assignment root A is a git-repo
--- ancestor of a concurrently-recording, nested assignment root B — e.g. two
--- active sessions from the same class repo — both sessions' own `-C` calls
--- can independently resolve to the SAME underlying `.git` and both correctly
--- report `'available'`. That is duplicate observation of one repository by
--- two sessions, not an ownership gap, and produces no `not_owned` case
--- either.)
---
--- `'not_owned'` stays a legal READ value (a bundle from a different producer
--- may use it), but this recorder's own writer never emits it. See
--- `recorder/session/recording_session.lua` for where `git_capture` is
--- derived.
---
--- Pure: no Neovim editor APIs beyond the `vim.NIL`/`vim.islist` value-model
--- primitives every other `core/` reader already uses. No I/O. Total: never
--- throws, never mutates.
local json = require("provenance.core.json")

local M = {}

-- ---------------------------------------------------------------------------
-- Field names
-- ---------------------------------------------------------------------------

M.GIT_CAPTURE_FIELD = "git_capture"
M.WITNESS_CAPTURE_FIELD = "witness_capture"
M.FILE_SCOPE_FIELD = "file_scope"

-- ---------------------------------------------------------------------------
-- §5.6 item 2 — was git observation available?
-- ---------------------------------------------------------------------------

--- Every legal value of `session.start.git_capture`, in a fixed order.
---
---  - `'available'` — the git integration answered and this session was
---    watching at least the repositories it owns. An absence of `git.event`
---    means git activity did not happen, not that it could not be seen.
---  - `'unavailable'` — the recorder could not observe git AT ALL on this
---    machine. Nothing this session did could have produced a `git.event`.
---  - `'not_owned'` — git observation worked, and every repository visible to
---    it was outside this session's assignment scope. See the module
---    docstring: this recorder's own writer never emits this value.
M.GIT_CAPTURE_VALUES = { "available", "unavailable", "not_owned" }

--- Every legal value of `session.start.witness_capture`, in a fixed order.
--- Two values, deliberately: there is no witnessing analogue of `not_owned`
--- because a recorder witnesses the `.provenance/` directory it is itself
--- writing into, so there is no ownership question to route on.
M.WITNESS_CAPTURE_VALUES = { "available", "unavailable" }

local function contains(list, value)
  for i = 1, #list do
    if list[i] == value then
      return true
    end
  end
  return false
end

-- ---------------------------------------------------------------------------
-- Reads
-- ---------------------------------------------------------------------------

-- JSON `null` reaches this module either as `vim.NIL` (raw `vim.json.decode`)
-- or as `json.NULL` (this port's own value model, e.g. after
-- `core.ndjson`'s normalize pass). Both are accepted as absence.
local function is_null(v)
  return v == nil or v == json.NULL or v == vim.NIL
end

--- Read one closed-enum capability field out of an untyped `session.start`
--- `data` value. Pure and total: never throws, never mutates. A `.slog` is a
--- student-editable file, so every input here is untrusted and a malformed
--- one is EXPECTED rather than exceptional.
---
--- `null` is accepted as absence so a writer that spelled the unknown case
--- explicitly still reads correctly — but a writer must OMIT the field.
---
--- A payload that is not an object at all reads as `'absent'`: there is no
--- field on a non-object.
--- @param data any
--- @param field string
--- @param legal string[]
--- @return table {kind="absent"} | {kind="recorded", capture=string} | {kind="malformed", problem=string}
local function read_enum_capability(data, field, legal)
  if type(data) ~= "table" or json.is_array(data) or data == json.NULL then
    return { kind = "absent" }
  end
  local raw = data[field]
  if is_null(raw) then
    return { kind = "absent" }
  end
  if type(raw) ~= "string" then
    return { kind = "malformed", problem = "not_a_string" }
  end
  if not contains(legal, raw) then
    return { kind = "malformed", problem = "unknown_value" }
  end
  return { kind = "recorded", capture = raw }
end

--- Read the git-capture report out of an untyped `session.start` `data` value.
--- @param data any
--- @return table
function M.read_git_capture(data)
  return read_enum_capability(data, M.GIT_CAPTURE_FIELD, M.GIT_CAPTURE_VALUES)
end

--- Read the witness-capture report out of an untyped `session.start` `data`
--- value.
--- @param data any
--- @return table
function M.read_witness_capture(data)
  return read_enum_capability(data, M.WITNESS_CAPTURE_FIELD, M.WITNESS_CAPTURE_VALUES)
end

-- ---------------------------------------------------------------------------
-- §5.6 item 1 — the effective resolved file set
-- ---------------------------------------------------------------------------

--- Reject anything that is not a scope-relative path. Returns the problem
--- code, or `nil` when `value` is acceptable. Mirrors log-core's
--- `pathProblem`: absolute first (so a Windows drive letter is diagnosed as
--- what it is, not as the colon rule below), then any colon (every
--- remote-URL spelling, including git's scp-style `user@host:path`), then a
--- `..` segment.
--- @param value any
--- @return string|nil
local function path_problem(value)
  if type(value) ~= "string" then
    return "path_not_a_string"
  end
  if #value == 0 then
    return "path_empty"
  end
  local first = value:sub(1, 1)
  if first == "/" or first == "\\" then
    return "path_absolute"
  end
  -- Windows drive letter: "C:", "C:\...", "C:/...".
  local c1, c2 = value:sub(1, 1), value:sub(2, 2)
  if c1:match("%a") ~= nil and c2 == ":" then
    local c3 = value:sub(3, 3)
    if #value == 2 or c3 == "\\" or c3 == "/" then
      return "path_absolute"
    end
  end
  if value:find(":", 1, true) ~= nil then
    return "path_has_colon"
  end
  local start = 1
  local len = #value
  while start <= len do
    local idx = value:find("[\\/]", start)
    local segment
    if idx then
      segment = value:sub(start, idx - 1)
      start = idx + 1
    else
      segment = value:sub(start)
      start = len + 1
    end
    if segment == ".." then
      return "path_escapes_scope"
    end
  end
  return nil
end
M._path_problem = path_problem -- test seam

--- Read the effective resolved file set out of an untyped `session.start`
--- `data` value. Mirrors log-core's `readFileScope`: a malformed ELEMENT
--- rejects the WHOLE set, because dropping only the offending entry would
--- hand a consumer a silently narrowed list, and a narrowed list read as
--- complete says "this file was not watched" about a file that was.
---
--- An empty `watched` with `complete: true` is a real, meaningful answer (the
--- scope resolved to nothing) and must not be folded into absence.
--- @param data any
--- @return table {kind="absent"} | {kind="recorded", watched=string[], complete=boolean} | {kind="malformed", problem=string}
function M.read_file_scope(data)
  if type(data) ~= "table" or json.is_array(data) or data == json.NULL then
    return { kind = "absent" }
  end
  local raw = data[M.FILE_SCOPE_FIELD]
  if is_null(raw) then
    return { kind = "absent" }
  end
  if type(raw) ~= "table" or json.is_array(raw) then
    return { kind = "malformed", problem = "not_an_object" }
  end

  local watched = raw.watched
  if type(watched) ~= "table" or not json.is_array(watched) then
    return { kind = "malformed", problem = "watched_not_an_array" }
  end

  local complete = raw.complete
  if type(complete) ~= "boolean" then
    return { kind = "malformed", problem = "complete_not_a_boolean" }
  end

  for i = 1, #watched do
    local problem = path_problem(watched[i])
    if problem ~= nil then
      return { kind = "malformed", problem = problem }
    end
  end

  return { kind = "recorded", watched = watched, complete = complete }
end

--- Build a `file_scope` value for a writer.
---
--- Returns `nil` when there is nothing honest to report (any entry fails
--- `path_problem`), which the caller must assign to the payload key directly
--- (a Lua `nil` assigned to a table key already omits it) — never spread as
--- `core_json.NULL`.
--- @param watched string[]
--- @param complete boolean
--- @return table|nil {watched=json.array(string[]), complete=boolean}
function M.build_file_scope(watched, complete)
  watched = watched or {}
  for i = 1, #watched do
    if path_problem(watched[i]) ~= nil then
      return nil
    end
  end
  local copied = {}
  for i = 1, #watched do
    copied[i] = watched[i]
  end
  -- TAGGED so an empty list canonicalizes as `[]`, not `{}` — the whole
  -- reason `watched` must serialize as a JSON array even when it is empty.
  return { watched = json.array(copied), complete = complete == true }
end

return M
