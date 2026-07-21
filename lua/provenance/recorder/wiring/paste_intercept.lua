--- paste_intercept.lua — signal 2 of three-signal paste detection (Plan 6,
--- Task 5): wraps the global `vim.paste` so every paste (register `p`/`P`
--- AND bracketed/terminal paste — Neovim routes both through this single
--- seam, `:help paste`) is observed before it applies.
---
--- VS Code analogue: packages/recorder/src/wiring/paste-command-intercept.ts.
--- VS Code cannot override its built-in paste command (registerCommand on a
--- built-in ID throws), so that port registers a SEPARATE opt-in command
--- course staff must rebind a keystroke to. Neovim has no such restriction:
--- `vim.paste` is a plain global function slot Neovim itself calls for every
--- paste, so this module can wrap it directly and unconditionally — no
--- opt-in keybinding, no signal degradation for sessions that don't install
--- one.
---
--- `vim.paste(lines, phase)`: `phase == -1` is a whole paste in one call;
--- `1`/`2`/`3` are the start/continue/end of a streamed (chunked) paste.
--- Neovim also hands `lines` directly, so unlike VS Code's command intercept
--- (which only gets a timestamp), this seam gets the pasted content for free
--- — but the clipboard register (`+`, falling back to `*`) is preferred over
--- `lines` because it holds the FULL paste text even when the paste is
--- streamed across phases; `lines` is only the fallback for a paste that
--- didn't originate from the clipboard (e.g. a terminal bracketed paste with
--- no register write).
local M = {}

--- capture_text(lines) -> string
---
--- Clipboard-then-lines fallback: prefer the system clipboard register
--- (`+`), then the selection register (`*`), then the lines Neovim handed
--- us. `vim.fn.getreg` never returns nil for an unset register (empty
--- string), so each step is just an emptiness check.
local function capture_text(lines)
  local plus = vim.fn.getreg("+")
  if plus ~= nil and plus ~= "" then
    return plus
  end
  local star = vim.fn.getreg("*")
  if star ~= nil and star ~= "" then
    return star
  end
  return table.concat(lines, "\n")
end

-------------------------------------------------------------------------
-- Ref-counted singleton wrap (concurrency): `vim.paste` is a single global
-- function slot, not an event-dispatch surface like an autocmd group. N
-- concurrent sessions must NOT each independently wrap it (nested wraps
-- unwind incorrectly on non-LIFO dispose -- see this module's docstring in
-- the implementation plan). Instead, the FIRST attach() installs the one
-- real wrap and captures the one true `original`; every attach()/dispose()
-- after that only registers/unregisters a listener in `listeners`. The true
-- original is restored only when the listener list becomes empty, so
-- dispose() order never matters.
-------------------------------------------------------------------------

local listeners = {} -- list of { on_intercept, get_now }
local true_original = nil -- vim.paste as it was before the FIRST attach()
local installed = false

local function broadcast(lines, phase)
  if phase == -1 or phase == 1 then
    local text = capture_text(lines)
    -- Snapshot the listener list: a listener's on_intercept could (in
    -- principle) dispose itself or another instance re-entrantly; iterate
    -- over a copy so that never corrupts this loop.
    local snapshot = {}
    for i, l in ipairs(listeners) do
      snapshot[i] = l
    end
    for _, l in ipairs(snapshot) do
      if l.on_intercept then
        local at = l.get_now and l.get_now() or nil
        pcall(l.on_intercept, text, at)
      end
    end
  end
end

local function install()
  if installed then
    return
  end
  installed = true
  true_original = vim.paste
  vim.paste = function(lines, phase)
    -- Capture the shared `true_original` upvalue into a call-local before
    -- broadcasting: a listener's on_intercept can synchronously dispose()
    -- another (or itself), and if that drops the listener count to zero
    -- mid-broadcast, uninstall_if_empty() clears the module-level
    -- `true_original` to nil out from under this still-executing call. Using
    -- the local ensures the REAL underlying vim.paste is still delegated to
    -- for THIS invocation, even though the module has already "uninstalled".
    local original_at_this_call = true_original
    pcall(broadcast, lines, phase)
    if original_at_this_call then
      return original_at_this_call(lines, phase)
    end
    return true
  end
end

local function uninstall_if_empty()
  if installed and #listeners == 0 then
    vim.paste = true_original
    installed = false
    true_original = nil
  end
end

--- M.attach(opts) -> handle
---
--- opts:
---   on_intercept(text, at) — called ONCE per paste (whole or start-of-
---     streamed), wrapped in pcall so an error here can never break the
---     user's paste, and can never break another concurrent listener either.
---   get_now() -> number — injected clock.
---
--- Returns a handle with handle.dispose(), idempotent, safe to call in any
--- order relative to other concurrently-attached instances' dispose().
function M.attach(opts)
  opts = opts or {}

  install()

  local entry = { on_intercept = opts.on_intercept, get_now = opts.get_now }
  table.insert(listeners, entry)

  local disposed = false
  local handle = {}

  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    for i, l in ipairs(listeners) do
      if l == entry then
        table.remove(listeners, i)
        break
      end
    end
    uninstall_if_empty()
  end

  return handle
end

--- Test-only introspection: how many live (non-disposed) registrations
--- exist right now. Not part of the module's production API.
function M._listener_count()
  return #listeners
end

return M
