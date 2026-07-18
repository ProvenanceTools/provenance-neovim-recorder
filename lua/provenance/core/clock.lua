--- Injectable clock: monotonic `t` (ms) + fixed-width ISO `wall`.
--- Mirrors log-core's clock seam so tests can inject deterministic time.
--- format_wall guards the provjet regression: millis must always be 3
--- digits, including ".000" — a formatter that drops zero millis breaks
--- the analyzer's monotonic-wall check.

local M = {}

--- Format an epoch-ms timestamp as "YYYY-MM-DDTHH:MM:SS.mmmZ" in UTC.
--- Milliseconds are always zero-padded to 3 digits.
function M.format_wall(epoch_ms)
  local seconds = math.floor(epoch_ms / 1000)
  local millis = epoch_ms % 1000
  local date_part = os.date("!%Y-%m-%dT%H:%M:%S", seconds)
  return string.format("%s.%03dZ", date_part, millis)
end

--- Real clock: monotonic now() via vim.uv.hrtime(), wall() via
--- vim.uv.gettimeofday() (second + microsecond granularity).
function M.system()
  return {
    now = function()
      return vim.uv.hrtime() / 1e6
    end,
    wall = function()
      local sec, usec = vim.uv.gettimeofday()
      local epoch_ms = sec * 1000 + math.floor(usec / 1000)
      return M.format_wall(epoch_ms)
    end,
  }
end

--- Deterministic test double. now_ms/wall_ms default to 0.
--- advance(ms) moves both now_ms and wall_ms forward by the same delta.
--- set_now(ms)/set_wall(ms) set each independently.
function M.fixed(now_ms, wall_ms)
  local state = { now_ms = now_ms or 0, wall_ms = wall_ms or 0 }

  return {
    now = function()
      return state.now_ms
    end,
    wall = function()
      return M.format_wall(state.wall_ms)
    end,
    advance = function(ms)
      state.now_ms = state.now_ms + ms
      state.wall_ms = state.wall_ms + ms
    end,
    set_now = function(ms)
      state.now_ms = ms
    end,
    set_wall = function(ms)
      state.wall_ms = ms
    end,
  }
end

return M
