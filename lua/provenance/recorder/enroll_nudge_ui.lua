--- Neovim glue for the enrollment nudge. The decision -- whether to show, and
--- what to persist afterwards -- lives in `enroll_nudge.lua` as pure functions;
--- this module reads the persisted state, renders the notification, and opens
--- the page on request.
---
--- ## Why there are no buttons
---
--- `vim.notify` carries no actions, and a `vim.ui.select` at startup would steal
--- the student's cursor the moment they open a file -- hostile in an editor
--- whose users chose it for staying out of the way. So the nudge is a plain
--- notification naming the URL and the two commands, and the state advances on
--- DISPLAY. The lifetime ceiling of two is unchanged; only the reason the second
--- one is the last differs from the other recorders.
---
--- ## Where the state lives
---
--- `stdpath("data")/provenance/enroll-nudge.json`, alongside `identity.json`.
--- Per machine and shared by every project, as a global 2.1 credential deserves.
--- Not a secret: it records only whether a notification has been shown.

local enroll_nudge = require("provenance.recorder.enroll_nudge")

local M = {}

--- @return string
local function state_path()
  return vim.fn.stdpath("data") .. "/provenance/enroll-nudge.json"
end

--- Read the persisted state. Any failure -- absent file, unreadable, corrupt
--- JSON, hand-edited nonsense -- reads as fresh, because the cost of showing a
--- nudge one extra time is a notification and the cost of throwing here is the
--- student's session.
--- @return string one of enroll_nudge.STATES
function M.read_state()
  local path = state_path()
  local ok, lines = pcall(vim.fn.readfile, path)
  if not ok or type(lines) ~= "table" or #lines == 0 then
    return enroll_nudge.STATES.UNSEEN
  end
  local decoded_ok, decoded = pcall(vim.json.decode, table.concat(lines, "\n"))
  if not decoded_ok or type(decoded) ~= "table" then
    return enroll_nudge.STATES.UNSEEN
  end
  return enroll_nudge.parse_state(decoded.state)
end

--- Persist the state, best effort. A write failure costs at most one repeated
--- notification; it must never surface to the student or stop anything.
--- @param state string
function M.write_state(state)
  pcall(function()
    local dir = vim.fn.stdpath("data") .. "/provenance"
    vim.fn.mkdir(dir, "p")
    vim.fn.writefile({ vim.json.encode({ state = state }) }, state_path())
  end)
end

--- Open the enrollment page in the student's browser.
---
--- `vim.ui.open` is the student's own action, invoked from their own keyboard.
--- The recorder opens no socket -- recorder PRD NG2 holds.
--- @return table { message = string, level = integer }
function M.open_enroll_page()
  local ok = pcall(function()
    vim.ui.open(enroll_nudge.ENROLL_URL)
  end)
  if ok then
    return {
      message = "Provenance: opened " .. enroll_nudge.ENROLL_URL,
      level = vim.log.levels.INFO,
    }
  end
  return {
    message = "Provenance: could not open a browser. Enrol at " .. enroll_nudge.ENROLL_URL,
    level = vim.log.levels.WARN,
  }
end

--- Render the enrollment state, if it is time.
---
--- Called once activation has settled, because only then does the registry hold
--- the outcomes this reads. Never throws into activation: a failed nudge costs a
--- notification, and a throw here would cost the recording.
--- @param registry table  the session registry (needs identity_outcomes())
--- @param deps table|nil  { notify, read_state, write_state } -- test seams
function M.maybe_nudge(registry, deps)
  deps = deps or {}
  local notify = deps.notify or vim.notify
  local read_state = deps.read_state or M.read_state
  local write_state = deps.write_state or M.write_state

  pcall(function()
    if not registry or type(registry.identity_outcomes) ~= "function" then
      return
    end
    local outcomes = registry.identity_outcomes()
    local state = read_state()
    if not enroll_nudge.should_show(outcomes, state) then
      return
    end
    notify(enroll_nudge.MESSAGE, vim.log.levels.WARN)
    write_state(enroll_nudge.next_state(state, enroll_nudge.ACTIONS.DISPLAYED))
  end)
end

return M
