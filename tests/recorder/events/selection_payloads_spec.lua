--- selection_payloads: pure builder for the selection.change event shape.
local selection_payloads = require("provenance.recorder.events.selection_payloads")

describe("selection_payloads.build_selection_change", function()
  it("wraps path/range/was_selection into the selection.change event shape", function()
    local range = {
      start = { line = 0, character = 2 },
      ["end"] = { line = 0, character = 2 },
    }
    local ev = selection_payloads.build_selection_change("foo.py", range, false)
    assert.equals("selection.change", ev.kind)
    assert.equals("foo.py", ev.data.path)
    assert.same(range, ev.data.range)
    assert.equals(false, ev.data.was_selection)
  end)

  it("preserves was_selection = true", function()
    local range = {
      start = { line = 1, character = 0 },
      ["end"] = { line = 1, character = 4 },
    }
    local ev = selection_payloads.build_selection_change("a.txt", range, true)
    assert.equals(true, ev.data.was_selection)
  end)
end)
