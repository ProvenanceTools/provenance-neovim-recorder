--- terminal_wiring: the Neovim seam between TermOpen/TermRequest/TermClose
--- and terminal.open/terminal.command (Plan 7, Task 5). Ports the intent of
--- the monorepo's terminal wiring, degrading gracefully wherever Neovim's
--- terminal API can't observe what VS Code's shell-integration API can.
---
--- FORMAT NOTE (CLAUDE.md — do not redesign the contract): log-core defines
--- only `terminal.open` and `terminal.command` — there is NO `terminal.close`
--- event. TermClose here is therefore INTERNAL BOOKKEEPING ONLY (forgetting
--- the terminal so a later, unrelated TermRequest on a reused bufnr can't be
--- misattributed) and emits nothing. Inventing a close event would be an
--- approval-gated format change owned by the Provenance monorepo, not a
--- decision for this port to make unilaterally.
---
--- shell_integration is always emitted as `false` at TermOpen time: OSC-133
--- markers (the shell-integration protocol) can only be confirmed once one
--- actually arrives via TermRequest, which happens well after the terminal
--- opens (if the configured shell emits them at all — most default shell
--- configs don't without opt-in setup). Recording `true` at open would be a
--- guess, not an observation; `false` is the honest "not yet confirmed"
--- default, matching the format's contract that `shell_integration` records
--- what was actually observable. A shell-integrated terminal's richer
--- command capture is a live-TUI manual-checklist item (see
--- docs/manual-verification.md) since a bare headless env never emits real
--- OSC-133 from a shell.
---
--- OSC-133 (real Neovim 0.12 shape, confirmed empirically with a literal
--- printf'd sequence in a live terminal): TermRequest's callback receives
--- `args.data.sequence`, e.g. "\27]133;C" (command start) or
--- "\27]133;D;0" (command finished, exit code 0) — WITHOUT the terminator
--- (that arrives separately as `args.data.terminator`). Parsing is
--- deliberately narrow and defensive: only a recognized "133;D[;<code>]"
--- command-finished marker emits `terminal.command`; anything else
--- (including "133;C" alone, or a garbled/unrecognized sequence) is ignored.
--- Command TEXT is best-effort and empty in v1 — Neovim doesn't hand this
--- seam the actual command line, only the OSC marker — the analyzer only
--- needs `terminal_id` + whatever exit_code is observable; the
--- `shell_integration=false` open-time fact already covers the no-capture
--- case.
local terminal_payloads = require("provenance.recorder.events.terminal_payloads")

local M = {}

local AUGROUP_NAME = "ProvenanceTerminal"

-- Concurrent multi-session support: see doc_wiring.lua's identical comment.
local instance_seq = 0

--- Best-effort realpath, falling back to plain normalize (mirrors
--- doc_wiring.lua's resolve_dir -- duplicated here rather than shared, since
--- neither module depends on the other).
local function resolve_dir(path)
  if not path then
    return nil
  end
  local normalized = vim.fs.normalize(path)
  local real = vim.uv.fs_realpath(normalized)
  return real and vim.fs.normalize(real) or normalized
end

--- is_under_workspace(cwd, workspace) -> boolean
---
--- True if `cwd` (a terminal's working directory) is `workspace` itself or a
--- descendant of it, after realpath-normalizing both sides the same way
--- doc_wiring.lua's is_recordable() does (symmetric regardless of which
--- side a symlink sits on).
local function is_under_workspace(cwd, workspace)
  if not workspace then
    return true -- no workspace filter configured: unchanged legacy behavior
  end
  local abs_cwd = resolve_dir(cwd)
  local abs_workspace = resolve_dir(workspace)
  if not abs_cwd or not abs_workspace then
    return false
  end
  return abs_cwd == abs_workspace or vim.startswith(abs_cwd, abs_workspace .. "/")
end

--- parse_osc133_command_finished(sequence) -> finished (boolean), exit_code (number|nil)
---
--- Pure, defensive parse of an OSC-133 sequence string. Recognizes a
--- command-finished marker ("...133;D" optionally followed by ";<exit_code>",
--- e.g. from "\27]133;D" or "\27]133;D;0" or "\27]133;D;137"). Anything else
--- — a command-start marker ("133;C"), a differently-shaped/garbled string,
--- or a non-string — is NOT finished and carries no exit_code. Exposed on M
--- so this parse logic is unit-testable directly, independent of the
--- TermRequest autocmd plumbing.
--- @param sequence any
--- @return boolean finished
--- @return number|nil exit_code
function M._parse_osc133_command_finished(sequence)
  if type(sequence) ~= "string" then
    return false, nil
  end
  if not sequence:find("133;D", 1, true) then
    return false, nil
  end
  local code_str = sequence:match("133;D;(%-?%d+)")
  local exit_code = code_str and tonumber(code_str) or nil
  return true, exit_code
end

--- detect_shell(buf) -> string
---
--- Best-effort, pcall-guarded shell detection. Prefers the terminal buffer's
--- own title (Neovim sets `b:term_title` to the job command line for a
--- plain `:terminal`), falling back to the globally configured `'shell'`,
--- falling back to "" — never throws, never blocks TermOpen.
local function detect_shell(buf)
  local ok, shell = pcall(function()
    local title = vim.b[buf].term_title
    if type(title) == "string" and title ~= "" then
      return title
    end
    local configured = vim.o.shell
    if type(configured) == "string" and configured ~= "" then
      return configured
    end
    return ""
  end)
  if ok and type(shell) == "string" then
    return shell
  end
  return ""
end

--- detect_terminal_id(buf) -> string
---
--- A stable id for the terminal: the job id if Neovim set one
--- (`b:terminal_job_id`, present for every real `:terminal`/`termopen`
--- buffer), else the buffer number itself. pcall-guarded so a detection
--- failure still yields a usable (buffer-number-based) id rather than
--- crashing TermOpen.
local function detect_terminal_id(buf)
  local ok, id = pcall(function()
    local job_id = vim.b[buf].terminal_job_id
    if job_id ~= nil then
      return tostring(job_id)
    end
    return tostring(buf)
  end)
  if ok and type(id) == "string" then
    return id
  end
  return tostring(buf)
end

--- start(opts) -> handle
---
--- opts:
---   emit: function(kind, data) — SessionHost.emit
---
--- Returns a handle with handle.dispose(). Idempotent; after dispose() no
--- further events emit and the augroup is gone.
function M.start(opts)
  opts = opts or {}
  local emit = opts.emit
  local workspace = opts.workspace

  local disposed = false

  -- buf -> { id = terminal_id, owned = boolean }, tracked from TermOpen
  -- through TermClose so a later TermRequest on the same buf can be
  -- attributed, and so TermRequest on an untracked buf (no prior TermOpen —
  -- shouldn't normally happen, but never trust autocmd ordering) is safely
  -- ignored. `owned` records whether this instance's workspace filter (if
  -- any) claimed the terminal, so a foreign terminal's TermRequest is
  -- silently ignored too, not just its TermOpen.
  local terminals = {}

  instance_seq = instance_seq + 1
  local augroup = vim.api.nvim_create_augroup(AUGROUP_NAME .. ":" .. instance_seq, { clear = true })

  vim.api.nvim_create_autocmd("TermOpen", {
    group = augroup,
    desc = "Provenance: terminal.open on terminal buffer creation (shell_integration=false until OSC-133 confirms otherwise)",
    callback = function(args)
      if disposed then
        return
      end
      -- Never let a detection/emit failure break terminal opening (CLAUDE.md
      -- graceful-degradation rule) — the whole body is pcall-guarded.
      pcall(function()
        local buf = args.buf
        local terminal_id = detect_terminal_id(buf)
        local owned = is_under_workspace(vim.fn.getcwd(), workspace)
        terminals[buf] = { id = terminal_id, owned = owned }

        if not owned then
          return -- not owned by this session: track silently, emit nothing
        end

        local shell = detect_shell(buf)
        local ev = terminal_payloads.build_terminal_open(terminal_id, shell, false)
        emit(ev.kind, ev.data)
      end)
    end,
  })

  vim.api.nvim_create_autocmd("TermRequest", {
    group = augroup,
    desc = "Provenance: OSC-133 command-finished marker -> terminal.command (best-effort; ignores anything else)",
    callback = function(args)
      if disposed then
        return
      end
      pcall(function()
        local buf = args.buf
        local tracked = terminals[buf]
        if not tracked or not tracked.owned then
          -- No tracked (owned) TermOpen for this buffer (e.g. TermRequest
          -- arrived before TermOpen was wired, for a buffer this module
          -- never saw, or for a foreign terminal not owned by this
          -- instance's workspace) — nothing to attribute the command to.
          return
        end
        local terminal_id = tracked.id

        local data = args.data
        local sequence = data and data.sequence
        local finished, exit_code = M._parse_osc133_command_finished(sequence)
        if not finished then
          return
        end

        -- Command text is best-effort/empty in v1 (see module docstring) —
        -- Neovim's OSC-133 marker carries no command-line text here.
        local ev = terminal_payloads.build_terminal_command(terminal_id, "", exit_code)
        emit(ev.kind, ev.data)
      end)
    end,
  })

  vim.api.nvim_create_autocmd("TermClose", {
    group = augroup,
    desc = "Provenance: internal cleanup only -- untrack the terminal; the format has no terminal.close event",
    callback = function(args)
      if disposed then
        return
      end
      pcall(function()
        terminals[args.buf] = nil
      end)
    end,
  })

  local handle = {}

  --- Idempotent: removes the augroup (so no further TermOpen/TermRequest/
  --- TermClose is observed) and clears tracked terminals.
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    pcall(vim.api.nvim_del_augroup_by_id, augroup)
    terminals = {}
  end

  handle._augroup_id = augroup

  return handle
end

return M
