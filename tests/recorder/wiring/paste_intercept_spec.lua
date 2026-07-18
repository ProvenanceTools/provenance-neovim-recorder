--- paste_intercept: the Neovim seam wrapping the global `vim.paste` — signal
--- 2 of three-signal paste detection (Plan 6, Task 5). Headless, invokes the
--- REAL `vim.paste` global (not a mock), since the whole point of this module
--- is Neovim's `vim.paste(lines, phase)` semantics.
local paste_intercept = require("provenance.recorder.wiring.paste_intercept")

--- Track everything created by a test so it can be torn down afterward:
--- buffers wiped, handle disposed (idempotent). Belt-and-braces per the
--- brief: a leaked global `vim.paste` override would corrupt every
--- subsequent paste-related spec in this headless process.
local function new_scratch()
  local scratch = { bufs = {}, handle = nil }

  function scratch.teardown()
    if scratch.handle then
      scratch.handle.dispose()
      scratch.handle = nil
    end
    for _, buf in ipairs(scratch.bufs) do
      if vim.api.nvim_buf_is_valid(buf) then
        pcall(vim.cmd, "bwipeout! " .. buf)
      end
    end
  end

  return scratch
end

local function new_capture()
  local calls = {}
  local function on_intercept(text, at)
    table.insert(calls, { text = text, at = at })
  end
  return calls, on_intercept
end

describe("paste_intercept.attach", function()
  local scratch

  before_each(function()
    scratch = new_scratch()
  end)

  after_each(function()
    scratch.teardown()
  end)

  it("intercepts a whole paste (-1), capturing clipboard text and applying the paste", function()
    local calls, on_intercept = new_capture()
    scratch.handle = paste_intercept.attach({
      on_intercept = on_intercept,
      get_now = function()
        return 1234
      end,
    })

    vim.fn.setreg("+", "pasted text")

    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)
    vim.api.nvim_set_current_buf(buf)

    vim.paste({ "pasted text" }, -1)

    assert.equals(1, #calls)
    assert.equals("pasted text", calls[1].text)
    assert.equals(1234, calls[1].at)

    -- The paste actually applied to the buffer (delegated to original).
    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    assert.equals("pasted text", table.concat(lines, "\n"))
  end)

  it("falls back to the pasted lines when both clipboard registers are empty", function()
    local calls, on_intercept = new_capture()
    scratch.handle = paste_intercept.attach({
      on_intercept = on_intercept,
      get_now = function()
        return 0
      end,
    })

    vim.fn.setreg("+", "")
    vim.fn.setreg("*", "")

    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)
    vim.api.nvim_set_current_buf(buf)

    vim.paste({ "from lines" }, -1)

    assert.equals(1, #calls)
    assert.equals("from lines", calls[1].text)
  end)

  it("intercepts exactly once for a streamed paste (phase 1 only, not 2/3)", function()
    local calls, on_intercept = new_capture()
    scratch.handle = paste_intercept.attach({
      on_intercept = on_intercept,
      get_now = function()
        return 42
      end,
    })

    vim.fn.setreg("+", "streamed")

    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)
    vim.api.nvim_set_current_buf(buf)

    vim.paste({ "a" }, 1)
    vim.paste({ "b" }, 2)
    vim.paste({ "c" }, 3)

    assert.equals(1, #calls)
    assert.equals(42, calls[1].at)
  end)

  it("dispose restores vim.paste exactly, and is idempotent", function()
    local orig = vim.paste

    local calls, on_intercept = new_capture()
    local handle = paste_intercept.attach({
      on_intercept = on_intercept,
      get_now = function()
        return 0
      end,
    })

    assert.is_not.equals(orig, vim.paste)

    handle.dispose()
    assert.equals(orig, vim.paste)

    -- Idempotent: a second dispose doesn't error and leaves vim.paste restored.
    assert.has_no.errors(function()
      handle.dispose()
    end)
    assert.equals(orig, vim.paste)
  end)

  it("an on_intercept error does not break the paste (wrapped in pcall)", function()
    scratch.handle = paste_intercept.attach({
      on_intercept = function()
        error("boom")
      end,
      get_now = function()
        return 0
      end,
    })

    local buf = vim.api.nvim_create_buf(false, true)
    table.insert(scratch.bufs, buf)
    vim.api.nvim_set_current_buf(buf)

    vim.fn.setreg("+", "still applies")

    assert.has_no.errors(function()
      vim.paste({ "still applies" }, -1)
    end)

    local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
    assert.equals("still applies", table.concat(lines, "\n"))
  end)
end)
