--- Builds the session.start payload (SessionStartPayload, PRD §5.1).
--- Pure(ish) function — every environment value (hostname, username, nvim
--- version, platform, recorder version, uuid generator) is injectable via
--- `env` so tests are fully deterministic. Mirrors log-core's
--- buildRecorderContext (recorder-context.ts).
---
--- CLAUDE.md: "test the event-to-log-entry transformation as a pure
--- function, separately from the editor wiring."
local core_sha256 = require("provenance.core.sha256")
local core_json = require("provenance.core.json")
local session_capabilities = require("provenance.core.session_capabilities")
local path_scope = require("provenance.core.path_scope")
local bit = require("bit")
local band, bor = bit.band, bit.bor

local M = {}

-- No package.json in a Neovim plugin; this is the single source of truth
-- for the recorder's own version until Plan 9 (dist) sources it centrally
-- (e.g. from a generated version file or the plugin manifest).
local PLUGIN_VERSION = "0.2.0"

--- The cap on `file_scope.watched`, in entries (collaboration spec §5.6
--- item 1). Today's resolver is the manifest's own `files_under_review` — a
--- hand-authored course list of a handful of files — so this never bites; it
--- exists so a future `scope: 'repo'` resolver cannot produce an unbounded
--- list inside a single hash-chained entry by accident. Part of the WRITER
--- CONTRACT: the three recorders must cap at the same number, or two ports
--- disagree about when `complete` goes false. Mirrors log-core's
--- `FILE_SCOPE_MAX_ENTRIES` (recorder-context.ts).
M.FILE_SCOPE_MAX_ENTRIES = 4096

--- Resolve the EFFECTIVE FILE SET this session will watch — collaboration
--- spec §5.6 item 1, S25. Today's resolver is the identity function:
--- `files_under_review` IS the effective set, because
--- `watch/fs_watcher.lua`/`watch/external_change_coordinator.lua` watch
--- exactly those entries.
---
--- RELATIVE TO WHAT: this recorder's activation keys off cwd, and the
--- manifest that supplies `files_under_review` lives at exactly
--- `<cwd>/.provenance-manifest` — so "workspace-relative" and "manifest-root
--- -relative" are the SAME base directory here, unlike a hypothetical layout
--- where the manifest could live somewhere other than the activated root.
--- Entries already travel verbatim as `<workspace>`-relative paths
--- everywhere else in this port (`doc.open.path`, `fs_watcher.lua`'s
--- `RelativePattern`-equivalent matching, the D12 root_commit_sha's own
--- workspace), which is the identical convention the VS Code reference
--- (`recorder-context.ts`) uses for `assignmentRoot`-relative paths. No
--- divergence needed: `file_scope.watched` is emitted exactly as
--- `files_under_review` already is, with no re-basing.
--- ## Rules make the list partial, not wrong
---
--- A manifest may now name a folder or a suffix (path-scope design spec §3).
--- Those entries cannot be enumerated at session start — that is the whole
--- point of naming one — so `watched` carries the exact-path entries only
--- and `complete` goes false whenever ANY rule entry is present, however few
--- exact entries there are. The analyzer then has two better answers
--- available before it falls back to `unknown`: it can evaluate the rules
--- itself against the signed manifest in `session.start`, and any file with
--- recorded activity was self-evidently watched.
---
--- @param files_under_review string[]|nil
--- @return table|nil SessionFileScope, or nil when nothing honest can be built
function M.resolve_file_scope(files_under_review)
  local list = files_under_review or {}
  -- A rule entry cannot be enumerated, so it cannot go in `watched` — and its
  -- presence means absence from `watched` no longer proves "not watched".
  -- `complete: false` is precisely the downgrade-to-unknown this field
  -- already defines for the truncation case; rules reuse it unchanged.
  local exact = {}
  for i = 1, #list do
    if path_scope.is_exact_entry(list[i]) then
      exact[#exact + 1] = list[i]
    end
  end
  local has_rules = #exact ~= #list
  local complete = not has_rules and #exact <= M.FILE_SCOPE_MAX_ENTRIES
  local watched = exact
  if #exact > M.FILE_SCOPE_MAX_ENTRIES then
    watched = {}
    for i = 1, M.FILE_SCOPE_MAX_ENTRIES do
      watched[i] = exact[i]
    end
  end
  return session_capabilities.build_file_scope(watched, complete)
end

-- Pinned producer id (design.md §6 / CLAUDE.md "Producer identity"): this is
-- how the analyzer distinguishes hosts. Never rename or derive this.
local EXTENSION_ID = "com.provenance.recorder.nvim"

--- Generate a UUID v4 (RFC 4122) from 16 random bytes, lowercase hex,
--- version nibble forced to 4 and variant bits forced to 10xx.
local function generate_uuid()
  local uv = vim.uv or vim.loop
  local bytes = uv.random(16)

  local b = {}
  for i = 1, 16 do
    b[i] = string.byte(bytes, i)
  end

  b[7] = bor(band(b[7], 0x0F), 0x40) -- version 4
  b[9] = bor(band(b[9], 0x3F), 0x80) -- variant 10xx

  local hex = {}
  for i = 1, 16 do
    hex[i] = string.format("%02x", b[i])
  end

  return table.concat(hex, "", 1, 4)
    .. "-"
    .. table.concat(hex, "", 5, 6)
    .. "-"
    .. table.concat(hex, "", 7, 8)
    .. "-"
    .. table.concat(hex, "", 9, 10)
    .. "-"
    .. table.concat(hex, "", 11, 16)
end

local function default_username()
  return os.getenv("USER") or os.getenv("USERNAME") or "unknown"
end

local function default_hostname()
  local uv = vim.uv or vim.loop
  local ok, uname = pcall(function() return uv.os_uname() end)
  if ok and uname and uname.nodename and uname.nodename ~= "" then
    return uname.nodename
  end
  local ok2, name = pcall(vim.fn.hostname)
  if ok2 and name and name ~= "" then
    return name
  end
  return "unknown"
end

local function default_platform()
  local uv = vim.uv or vim.loop
  local ok, uname = pcall(function() return uv.os_uname() end)
  if ok and uname and uname.sysname then
    return uname.sysname
  end
  return "unknown"
end

local function default_nvim_version()
  local ok, v = pcall(vim.version)
  if not ok or not v then
    return "unknown"
  end
  return string.format("%d.%d.%d", v.major or 0, v.minor or 0, v.patch or 0)
end

--- Compute machine_id = sha256Hex(hostname .. ":" .. username .. ":" .. session_id).
--- session_id is a per-session salt (mirrors log-core's computeMachineId).
local function compute_machine_id(hostname, username, session_id)
  return core_sha256.hex(hostname .. ":" .. username .. ":" .. session_id)
end

--- Build the `manifest` block carried by session.start 2.0 (program spec §5):
--- the FULL manifest — payload + sig +, at 2.0, `course_cert` and `policy`.
---
--- Emitted for 1.x manifests too. That is the point: it is what lets the
--- analyzer apply the ABSENCE-VS-DISABLED rule, i.e. tell "this student
--- produced no selection.change events" from "this course disabled
--- selection.change" — a distinction heuristics otherwise mis-fire on. A 1.x
--- manifest simply carries no policy, which reads as the default capture set.
---
--- `files_under_review` is re-tagged as a json.array so it canonicalizes as
--- `[...]` and not `{...}`: this payload is hashed into the chain, and an
--- untagged list from a hand-built manifest would produce different bytes.
--- Fields are copied by name rather than by table copy so an unknown key on the
--- source manifest can never silently enter the signed chain.
local function build_manifest_block(m)
  local block = {
    assignment_id = m.assignment_id,
    semester = m.semester,
    issued_at = m.issued_at,
    files_under_review = core_json.array(m.files_under_review or {}),
    sig = m.sig,
  }

  -- Absent on a hand-built 1.x manifest; core.manifest.parse always sets it.
  block.format_version = m.format_version

  -- 2.0-only. Nil assignment is a no-op in Lua, so a 1.x manifest simply omits
  -- every one of these and its block is exactly the 1.x manifest.
  block.course_id = m.course_id
  block.collaboration = m.collaboration
  block.submission = m.submission
  block.scope = m.scope
  block.policy = m.policy
  block.course_cert = m.course_cert

  -- `ignore` and `attachments`: REQUIRED fields of a 2.0 manifest (path-scope
  -- design spec §3), so a 2.0 manifest missing either fails core.manifest's
  -- own parse and never reaches here — but this block re-derives the signed
  -- payload from scratch by copying named fields, and until these two lines
  -- existed neither was among them. That silently dropped two SIGNED fields
  -- from the emitted session.start manifest, so `manifest.verify_chain`
  -- (correctly) refused to re-verify it: the analyzer's whole offline
  -- root->course->manifest->session trust walk failed for every 2.0 session
  -- this recorder recorded.
  --
  -- Guarded (not `core_json.array(m.ignore)` unconditionally) because
  -- `core_json.array(nil)` returns an EMPTY array, not nil — it would
  -- materialize `ignore = []` on a 1.x manifest, which has neither field, and
  -- an invented empty array is a key an unguarded assignment would not have
  -- produced. `m.ignore`/`m.attachments` are already json.array-tagged by
  -- core.manifest's own `normalize()` when they came from `parse()`, but a
  -- hand-built manifest table might not tag them, so they are re-tagged here
  -- too, the same reasoning `files_under_review` above already follows.
  if m.ignore ~= nil then
    block.ignore = core_json.array(m.ignore)
  end
  if m.attachments ~= nil then
    block.attachments = core_json.array(m.attachments)
  end

  return block
end

--- @param opts table {manifest, prev_session_id, session_pubkey_hex, identity?, env?, git_capture?, witness_capture?}
---   manifest: table with assignment_id, semester, sig, files_under_review.
---   identity: the verified session.start identity block, or nil to omit it.
---   prev_session_id: string or nil (fresh session).
---   session_pubkey_hex: string or nil.
---   env: optional overrides — uuid (function -> string), hostname, username,
---     nvim_version, platform, recorder_version.
---   git_capture: the §5.6 item 2 capability report ("available" |
---     "unavailable" | "not_owned"), or nil to OMIT the field. Derived by the
---     caller from `git_wiring.start()`'s `.active` — see
---     `recorder/session/recording_session.lua`, which is also where the
---     `'not_owned'` non-emission is explained.
---   witness_capture: the §5.6 item 3 capability report ("available" |
---     "unavailable"). Derived by the caller from `peer_watcher.start()`'s
---     `._watching`. Unlike `git_capture` this recorder always has an answer
---     (creating the `.provenance/` watcher either succeeds or it does not),
---     so callers should pass a value rather than nil.
--- @return table SessionStartPayload
function M.build_recorder_context(opts)
  opts = opts or {}
  local manifest = opts.manifest
  local env = opts.env or {}

  local uuid_fn = env.uuid or generate_uuid
  local session_id = uuid_fn()

  local hostname = env.hostname or default_hostname()
  local username = env.username or default_username()
  local nvim_version = env.nvim_version or default_nvim_version()
  local platform = env.platform or default_platform()
  local recorder_version = env.recorder_version or PLUGIN_VERSION

  local machine_id = compute_machine_id(hostname, username, session_id)

  local prev_session_id = opts.prev_session_id
  if prev_session_id == nil then
    prev_session_id = core_json.NULL
  end

  -- The three CAPABILITY REPORTS (collaboration spec §5.6). Each field is
  -- assigned directly, never through `core_json.NULL`: a Lua `nil` assigned
  -- to a table key already omits it, which is the OMIT-never-null rule this
  -- format requires (see core/session_capabilities.lua's module docstring).
  -- `file_scope` is resolved HERE, from the manifest already in scope,
  -- mirroring log-core's `resolveFileScope(manifest.files_under_review)`.
  local file_scope = M.resolve_file_scope(manifest.files_under_review)

  return {
    format_version = "1.0",
    session_id = session_id,
    prev_session_id = prev_session_id,
    assignment = {
      id = manifest.assignment_id,
      semester = manifest.semester,
    },
    manifest_sig = manifest.sig,
    machine_id = machine_id,
    -- The FULL manifest (program spec §5). NEW in 2.0, additive: 1.x readers
    -- ignore what they do not know.
    manifest = build_manifest_block(manifest),
    -- RETAINED for 1.x readers, which look here for the host triple. `host`
    -- below is its 2.0 replacement; both are emitted during the transition.
    vscode = {
      version = nvim_version,
      commit = "",
      platform = platform,
    },
    -- NEW in 2.0 (program spec §5, §S2): the student identity block, present
    -- ONLY when a verified one could be built. `opts.identity` is nil whenever
    -- the student is unenrolled, the secret store is unreadable, or the chain
    -- walk failed — and a nil assignment in Lua leaves the key ABSENT, which is
    -- exactly what the spec requires: never nil-valued, never an empty table.
    -- An identity that cannot be verified is omitted rather than written,
    -- because session.start is signed and hash-chained and a broken claim in
    -- there is permanent. See identity/session_identity.lua.
    identity = opts.identity,
    -- The three §5.6 CAPABILITY REPORTS. Each is nil-omitted, never
    -- `core_json.NULL`, when the caller has nothing honest to report.
    git_capture = opts.git_capture,
    witness_capture = opts.witness_capture,
    file_scope = file_scope,
    -- NEW in 2.0: the editor-neutral host block that replaces `vscode`.
    -- `editor_build` is "" because Neovim has no build-commit concept — the
    -- spec explicitly permits the empty string (VS Code does not expose one
    -- either).
    host = {
      editor = "neovim",
      editor_version = nvim_version,
      editor_build = "",
      platform = platform,
    },
    recorder = {
      version = recorder_version,
      extension_id = EXTENSION_ID,
    },
    session_pubkey = opts.session_pubkey_hex or "",
  }
end

return M
