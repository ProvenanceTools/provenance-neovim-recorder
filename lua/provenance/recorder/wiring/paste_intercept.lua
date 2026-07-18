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

--- M.attach(opts) -> handle
---
--- opts:
---   on_intercept(text, at) — called ONCE per paste (see phase handling
---     below), wrapped in pcall so an error here can never break the user's
---     paste.
---   get_now() -> number — injected clock.
---
--- Returns a handle with handle.dispose() that restores the original
--- `vim.paste`. Idempotent.
function M.attach(opts)
  opts = opts or {}
  local on_intercept = opts.on_intercept
  local get_now = opts.get_now

  local original = vim.paste
  local disposed = false

  --- @param lines string[]
  --- @param phase integer  -1 (whole paste) | 1 (start) | 2 (continue) | 3 (end)
  vim.paste = function(lines, phase)
    -- Notify on the START of a paste only (-1 = whole paste in one call, 1 =
    -- start of a streamed paste) so a chunked paste yields exactly one
    -- intercept, not one per phase.
    if phase == -1 or phase == 1 then
      local text = capture_text(lines)
      if on_intercept then
        pcall(on_intercept, text, get_now and get_now() or nil)
      end
    end

    -- ALWAYS delegate so the paste actually applies, including every
    -- streamed phase. Guard the unusual case of no prior vim.paste (Neovim
    -- always sets a default, but don't hard-crash if something removed it).
    if original then
      return original(lines, phase)
    end
    return true
  end

  local handle = {}

  --- Restores `vim.paste` to exactly the function captured at attach()
  --- time. Idempotent — a second call is a harmless no-op, guarded by the
  --- `disposed` flag (mirrors doc_wiring.lua's dispose pattern).
  function handle.dispose()
    if disposed then
      return
    end
    disposed = true
    vim.paste = original
  end

  return handle
end

return M
