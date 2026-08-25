--- Path scope — the ONLY matcher that decides whether a path is in scope.
---
--- Design spec: `docs/superpowers/specs/2026-08-22-path-scope-design.md` §3 in
--- the monorepo. Lua port of log-core's `path-scope.ts`.
---
--- ## Why three forms and not a glob
---
--- This rule is hand-implemented three times: here, in provjet (Kotlin), and
--- in the monorepo (TypeScript). A real glob engine written three times is
--- three chances for the same manifest to watch different files on different
--- editors — the exact divergence the parent spec exists to prevent. Keeping
--- the rule to three forms (exact path, directory prefix, filename suffix)
--- makes it small enough that a port cannot plausibly get it wrong, and
--- `tests/conformance/fixtures/path-scope-vectors.json` pins the answer for
--- every case across all three ports.
---
--- ## Why matching is byte-exact
---
--- No separator normalization, no `.` resolution, no case folding. Normalizing
--- on any one of those axes would make two recorders' spellings of the same
--- path compare equal here and unequal everywhere else in the system. macOS
--- being case-insensitive on disk is a known, accepted consequence — it is the
--- same behaviour the legacy exact-path `files_under_review` list has always
--- had.
---
--- ## The editor's glob is never the authority
---
--- A recorder may hand a directory or suffix entry to Neovim's file watcher as
--- a coarse pre-filter (e.g. `src/` -> a broad autocmd pattern). It MUST
--- re-check every resulting path against `M.matches_scope_entry` before
--- treating it as in scope. See the design spec §4.2 — a port that emits on
--- its watcher's verdict alone is a conformance failure, not a shortcut.
---
--- Pure: no Neovim editor APIs, no I/O. Total: never throws, never mutates its
--- arguments.

local M = {}

-- ---------------------------------------------------------------------------
-- Small local helpers (Lua has no Array#includes / String#startsWith etc.)
-- ---------------------------------------------------------------------------

local function starts_with(s, prefix)
  return s:sub(1, #prefix) == prefix
end

--- `endsWith("")` is TRUE by definition (every string ends with the empty
--- string). Kept correct even though the one caller that matters
--- (`matches_scope_entry`'s suffix branch) never reaches it with an empty
--- suffix: an entry of exactly `"*"` is rejected by `validate_scope_entry`,
--- so `entry:sub(2)` is never `""` for a validated entry.
local function ends_with(s, suffix)
  if suffix == "" then
    return true
  end
  return s:sub(-#suffix) == suffix
end

local function contains(list, value)
  for i = 1, #list do
    if list[i] == value then
      return true
    end
  end
  return false
end

--- Trim leading/trailing whitespace, where "whitespace" means what Lua's
--- `%s` class means: space, tab, newline, carriage return, form feed,
--- vertical tab — the same set `String.prototype.trim` treats as whitespace
--- for our purposes.
local function trim(s)
  return s:match("^%s*(.-)%s*$")
end

--- Split `s` on `/`, keeping empty segments (mirrors JS `String#split('/')`,
--- which for `""` yields `{""}`, not `{}`). Uses plain-mode `find` so `/`
--- is never mistaken for a Lua pattern metacharacter (it isn't one, but the
--- explicit `true` keeps this future-proof and matches this module's other
--- string-search calls).
local function split_on_slash(s)
  local segments = {}
  local start = 1
  while true do
    local idx = s:find("/", start, true)
    if idx == nil then
      segments[#segments + 1] = s:sub(start)
      break
    end
    segments[#segments + 1] = s:sub(start, idx - 1)
    start = idx + 1
  end
  return segments
end

-- ---------------------------------------------------------------------------
-- Hard exclusions — not course-controllable
-- ---------------------------------------------------------------------------

--- Never in scope, whatever the manifest says.
---
--- With the legacy exact-path list this came for free: nobody lists their own
--- provenance directory. With rules it does not — an `ignore` entry of
--- `"*.json"` would otherwise reach `.provenance/manifest.json`, and a broad
--- `attachments` entry could seal the log directory into itself.
M.HARD_EXCLUDED_PREFIXES = { ".provenance/", ".git/" }

M.HARD_EXCLUDED_PATHS = { ".provenance-manifest", "provenance-manifest" }

--- @param path string
--- @return boolean
function M.is_hard_excluded(path)
  for i = 1, #M.HARD_EXCLUDED_PREFIXES do
    if starts_with(path, M.HARD_EXCLUDED_PREFIXES[i]) then
      return true
    end
  end
  return contains(M.HARD_EXCLUDED_PATHS, path)
end

-- ---------------------------------------------------------------------------
-- Matching
-- ---------------------------------------------------------------------------

--- True iff `entry` is the exact-path form (neither the directory-prefix nor
--- the filename-suffix form).
--- @param entry string
--- @return boolean
function M.is_exact_entry(entry)
  return not (ends_with(entry, "/") or starts_with(entry, "*"))
end

--- The whole matching rule. Assumes `entry` has already passed
--- `M.validate_scope_entry` — a malformed entry is rejected at manifest parse
--- time and never reaches here.
---
--- Byte-exact and case-sensitive throughout: no `string.find`/`gsub` pattern
--- is used for the comparisons themselves (only for the plain-mode substring
--- search below), so none of `.`, `*`, `[`, `]`, `%`, `-`, `?`, `+`, `(`, `)`,
--- `^`, `$` inside a path or entry is ever treated as a Lua pattern
--- metacharacter.
--- @param path string
--- @param entry string
--- @return boolean
function M.matches_scope_entry(path, entry)
  if ends_with(entry, "/") then
    return starts_with(path, entry)
  end
  if starts_with(entry, "*") then
    return ends_with(path, entry:sub(2))
  end
  return path == entry
end

--- @param path string
--- @param entries string[]
--- @return boolean
function M.matches_any_scope_entry(path, entries)
  if entries == nil then
    return false
  end
  for i = 1, #entries do
    if M.matches_scope_entry(path, entries[i]) then
      return true
    end
  end
  return false
end

--- Precedence chain, design spec §3.4. First match wins:
--- excluded > ignored > attachment > reviewed > unscoped.
---
--- `scope` is a plain table `{ track = {...}, ignore = {...},
--- attachments = {...} }`; any of the three lists may be absent (`nil`),
--- which is treated as an empty list.
--- @param path string
--- @param scope table {track: string[]|nil, ignore: string[]|nil, attachments: string[]|nil}
--- @return string "excluded"|"ignored"|"attachment"|"reviewed"|"unscoped"
function M.resolve_path_role(path, scope)
  if M.is_hard_excluded(path) then
    return "excluded"
  end
  if M.matches_any_scope_entry(path, scope.ignore) then
    return "ignored"
  end
  if M.matches_any_scope_entry(path, scope.attachments) then
    return "attachment"
  end
  if M.matches_any_scope_entry(path, scope.track) then
    return "reviewed"
  end
  return "unscoped"
end

-- ---------------------------------------------------------------------------
-- Validation
-- ---------------------------------------------------------------------------

-- Checked in this exact order below — the vector file pins which single
-- problem kind is reported for an entry that violates more than one rule.
local FORBIDDEN_CHARS = { "?", "[", "]", "{", "}" }

--- Everything wrong with one entry, or `nil` if it is legal.
---
--- Runs at manifest PARSE time and rejects the manifest. A malformed entry is
--- a staff error that must be caught before a manifest is distributed to a
--- class, not a runtime surprise diagnosed weeks later.
---
--- @param entry string
--- @return table|nil {kind: string, detail: string}
function M.validate_scope_entry(entry)
  if #entry == 0 then
    return { kind = "empty", detail = "An entry may not be empty." }
  end
  if entry ~= trim(entry) then
    return {
      kind = "whitespace",
      detail = "An entry may not begin or end with whitespace. A trailing space is invisible here and "
        .. "produces an entry that matches nothing.",
    }
  end
  if entry:find("\\", 1, true) ~= nil then
    return {
      kind = "backslash",
      detail = "Use forward slashes. A backslash never matches, on any platform.",
    }
  end
  if starts_with(entry, "/") or entry:match("^%a:") ~= nil then
    return {
      kind = "absolute",
      detail = "An entry must be relative to the folder holding the manifest.",
    }
  end

  local _, star_count = entry:gsub("%*", "")
  if star_count > 1 or (star_count == 1 and not starts_with(entry, "*")) then
    return {
      kind = "bad_wildcard",
      detail = "The only wildcard is a single leading \"*\", which matches a filename suffix at any "
        .. "depth (e.g. \"*.java\"). There is no \"**\" and no mid-path wildcard.",
    }
  end
  if entry == "*" then
    return { kind = "bad_wildcard", detail = 'A leading "*" must be followed by a suffix.' }
  end
  -- A suffix entry that also ends in "/" validates as legal but is DEAD: the
  -- matcher tests the directory form first, so `*.java/` can only ever match
  -- a path that literally begins `*.java/`, which no workspace-relative path
  -- does. A course that wrote it would sign a manifest that watches nothing
  -- and find out weeks later. Rejecting at parse time is the whole point of
  -- this function — the two forms are mutually exclusive, so asking for both
  -- is always a mistake, never a shorthand.
  if starts_with(entry, "*") and ends_with(entry, "/") then
    return {
      kind = "bad_wildcard",
      detail = 'A leading "*" matches a filename suffix, so the entry may not also end with "/". '
        .. 'Write "*.java" to match files by suffix, or "java/" to match a directory.',
    }
  end

  for i = 1, #FORBIDDEN_CHARS do
    local c = FORBIDDEN_CHARS[i]
    if entry:find(c, 1, true) ~= nil then
      return {
        kind = "forbidden_char",
        detail = '"' .. c .. '" is not supported. The only forms are an exact path, a "dir/" prefix, '
          .. 'and a leading "*" suffix.',
      }
    end
  end

  -- Segment checks run on the path part only, so a leading "*" is not
  -- mistaken for a segment. A directory entry's trailing "/" produces a
  -- final empty segment that is legal, so it is dropped before checking.
  local path_part = starts_with(entry, "*") and entry:sub(2) or entry
  if ends_with(path_part, "/") then
    path_part = path_part:sub(1, -2)
  end
  local segments = split_on_slash(path_part)
  for i = 1, #segments do
    local seg = segments[i]
    if seg == "." or seg == ".." then
      return { kind = "dot_segment", detail = 'An entry may not contain a "." or ".." segment.' }
    end
    if #seg == 0 then
      return { kind = "empty_segment", detail = "An entry may not contain an empty path segment." }
    end
  end

  return nil
end

return M
