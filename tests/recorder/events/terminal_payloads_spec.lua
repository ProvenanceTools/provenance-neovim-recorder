local terminal_payloads = require("provenance.recorder.events.terminal_payloads")

describe("terminal_payloads.build_terminal_open", function()
  it("returns {kind, data} with terminal_id, shell, shell_integration", function()
    local ev = terminal_payloads.build_terminal_open("term123", "bash", true)
    assert.equals("terminal.open", ev.kind)
    assert.equals("term123", ev.data.terminal_id)
    assert.equals("bash", ev.data.shell)
    assert.equals(true, ev.data.shell_integration)
  end)

  it("includes shell_integration=false when explicitly false", function()
    local ev = terminal_payloads.build_terminal_open("term456", "/bin/zsh", false)
    assert.equals("terminal.open", ev.kind)
    assert.equals("term456", ev.data.terminal_id)
    assert.equals("/bin/zsh", ev.data.shell)
    assert.equals(false, ev.data.shell_integration)
  end)
end)

describe("terminal_payloads.build_terminal_command", function()
  it("includes exit_code when exit_code is 0", function()
    local ev = terminal_payloads.build_terminal_command("term123", "ls -la", 0)
    assert.equals("terminal.command", ev.kind)
    assert.equals("term123", ev.data.terminal_id)
    assert.equals("ls -la", ev.data.command)
    assert.equals(0, ev.data.exit_code)
  end)

  it("includes exit_code when exit_code is non-zero", function()
    local ev = terminal_payloads.build_terminal_command("term123", "false", 137)
    assert.equals("terminal.command", ev.kind)
    assert.equals("term123", ev.data.terminal_id)
    assert.equals("false", ev.data.command)
    assert.equals(137, ev.data.exit_code)
  end)

  it("omits exit_code key when exit_code is nil", function()
    local ev = terminal_payloads.build_terminal_command("term123", "echo hello", nil)
    assert.equals("terminal.command", ev.kind)
    assert.equals("term123", ev.data.terminal_id)
    assert.equals("echo hello", ev.data.command)
    assert.is_nil(ev.data.exit_code)
    -- Verify the key is actually absent (not just nil-valued)
    local has_exit_code = false
    for k in pairs(ev.data) do
      if k == "exit_code" then
        has_exit_code = true
        break
      end
    end
    assert.is_false(has_exit_code)
  end)
end)
